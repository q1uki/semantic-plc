#!/usr/bin/env python3
"""
S7comm Industrial Security Monitor - Production Grade (Custom Parser Edition)
架构：
1. Data Extraction: Scapy Sniff (TCP Layer) + Manual Byte Parsing (No contrib dependency)
2. Data Characterisation: 论文分类逻辑 (常量/属性/连续)
3. Modelling & Detection: 多模型融合 + scipy统计
"""

import logging
import warnings
import os
import time
import struct
import numpy as np
from datetime import datetime
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple, Optional, Set, Any

# 统计分析库
from scipy.stats import f
from statsmodels.tsa.ar_model import AutoReg

# Scapy 仅用于抓取 TCP 包，不依赖 s7 contrib
from scapy.all import sniff, PcapReader, TCP, IP, Raw

# Snap7 用于工业数据转换 (可选，如果解析失败则回退到手动 struct)
try:
    from snap7.util import get_real, get_int, get_dint, get_word, get_dword

    SNAP7_AVAILABLE = True
except ImportError:
    print("WARNING: Snap7 not found. Falling back to struct.")
    SNAP7_AVAILABLE = False

# -------------------------------------------------------------------------
# Logging Configuration
# -------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [S7-Monitor] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("S7-Monitor")
warnings.filterwarnings("ignore")


# -------------------------------------------------------------------------
# Data Structures & Enums
# -------------------------------------------------------------------------

class VariableType(Enum):
    """变量分类（论文Section 3.4）"""
    CONSTANT = "constant"  # 配置变量
    ATTRIBUTE = "attribute"  # 状态变量
    CONTINUOUS = "continuous"  # 传感器变量


@dataclass
class S7Variable:
    """S7变量对象"""
    timestamp: datetime
    plc_id: str
    tag_id: str  # 物理标签 (e.g., "DB1.DBD10")
    area: int  # 内存区域
    db_number: int  # DB块号
    address: int  # 字节地址
    value: Any  # 解析后的值
    data_type: str  # REAL/INT/DINT/WORD
    operation: str  # read/write


@dataclass
class VariableModel:
    """变量检测模型"""
    tag_id: str
    var_type: VariableType
    expected_values: Set[Any] = field(default_factory=set)  # 常量
    enumeration_set: Set[Any] = field(default_factory=set)  # 属性
    ar_model: Optional[Any] = None  # 连续
    control_limits: Tuple[float, float] = (0, 0)
    train_variance: float = 0
    history: deque = field(default_factory=lambda: deque(maxlen=5))
    residual_window: deque = field(default_factory=lambda: deque(maxlen=10))


@dataclass
class DetectionAlert:
    """检测告警"""
    timestamp: datetime
    tag_id: str
    alert_type: str
    severity: str
    expected: Any
    observed: Any
    details: str


# -------------------------------------------------------------------------
# Phase 1: Data Extraction Engine (Manual Byte Parsing)
# -------------------------------------------------------------------------

class S7DataExtractor:
    """
    S7 数据提取器 (修复版 V2 - 支持 I/Q/M/DB 全区域解析)
    """

    def __init__(self):
        self.shadow_memory: Dict[int, List[Dict]] = {}
        self.variables_extracted: List[S7Variable] = []

    def parse_packet(self, pkt) -> List[S7Variable]:
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return []

        payload = bytes(pkt[Raw].load)

        # 1. 寻找 S7 Header (0x32)
        s7_offset = -1
        # 快速检查
        if len(payload) > 5 and payload[0] == 0x03:
            cotp_len = payload[4]
            calc_offset = 5 + cotp_len
            if calc_offset < len(payload) and payload[calc_offset] == 0x32:
                s7_offset = calc_offset

        # 暴力搜索
        if s7_offset == -1:
            for i in range(len(payload) - 10):
                if payload[i] == 0x32 and payload[i + 1] in [1, 2, 3]:
                    s7_offset = i
                    break

        if s7_offset == -1: return []

        variables = []
        try:
            rosctr = payload[s7_offset + 1]
            tpdu_ref = struct.unpack('>H', payload[s7_offset + 4: s7_offset + 6])[0]
            param_len = struct.unpack('>H', payload[s7_offset + 6: s7_offset + 8])[0]

            header_len = 12 if rosctr == 3 else 10
            param_start = s7_offset + header_len
            data_start = param_start + param_len

            plc_id = pkt[IP].src if pkt.haslayer(IP) else "unknown"

            # === Job Request (Write) ===
            if rosctr == 1:
                func = payload[param_start]
                if func == 0x05:  # Write Var
                    vars_ = self._handle_write_request(payload, param_start, data_start, plc_id)
                    variables.extend(vars_)
                elif func == 0x04:  # Read Var (记账)
                    self._handle_read_request(payload, param_start, tpdu_ref)

            # === Ack_Data (Read) ===
            elif rosctr == 3:
                error_class = payload[s7_offset + 10]
                if error_class == 0:
                    vars_ = self._handle_read_response(payload, data_start, tpdu_ref, plc_id)
                    variables.extend(vars_)

        except Exception as e:
            pass  # 忽略解析错误的包

        # 过滤掉 value 为 None 的无效变量
        valid_vars = [v for v in variables if v.value is not None]
        self.variables_extracted.extend(valid_vars)
        return valid_vars

    def _handle_read_request(self, payload, param_start, tpdu_ref):
        try:
            item_count = payload[param_start + 1]
            curr = param_start + 2
            items = []
            for _ in range(item_count):
                if curr + 12 > len(payload): break
                len_ = struct.unpack('>H', payload[curr + 4:curr + 6])[0]
                db = struct.unpack('>H', payload[curr + 6:curr + 8])[0]
                area = payload[curr + 8]
                addr_raw = (payload[curr + 9] << 16) | (payload[curr + 10] << 8) | payload[curr + 11]

                # 记录 transport size 以便后续正确解析长度
                trans_type = payload[curr + 3]

                items.append({'area': area, 'db': db, 'start': addr_raw >> 3, 'len': len_, 'type': trans_type})
                curr += 12

            if items:
                self.shadow_memory[tpdu_ref] = items
        except:
            pass

    def _handle_write_request(self, payload, param_start, data_start, plc_id):
        variables = []
        try:
            item_count = payload[param_start + 1]

            # 1. Parameter (Address)
            items_meta = []
            curr_p = param_start + 2
            for _ in range(item_count):
                len_ = struct.unpack('>H', payload[curr_p + 4:curr_p + 6])[0]
                db = struct.unpack('>H', payload[curr_p + 6:curr_p + 8])[0]
                area = payload[curr_p + 8]
                addr_raw = (payload[curr_p + 9] << 16) | (payload[curr_p + 10] << 8) | payload[curr_p + 11]
                items_meta.append({'area': area, 'db': db, 'addr': addr_raw >> 3, 'len': len_})
                curr_p += 12

            # 2. Data (Values)
            curr_d = data_start
            for meta in items_meta:
                if curr_d + 4 > len(payload): break

                ret_code = payload[curr_d]
                trans_size = payload[curr_d + 1]
                raw_len = struct.unpack('>H', payload[curr_d + 2:curr_d + 4])[0]

                # 计算长度 (Bits vs Bytes)
                if trans_size in [0x03, 0x04, 0x05]:  # Bit/Word/Int -> bits
                    byte_len = (raw_len + 7) // 8
                else:
                    byte_len = raw_len  # Bytes

                val_start = curr_d + 4
                raw_bytes = payload[val_start: val_start + byte_len]

                # 调用修复后的转换函数
                tag_id, value, dtype = self._convert_value(meta['area'], meta['db'], meta['addr'], raw_bytes)

                if tag_id and value is not None:
                    variables.append(S7Variable(
                        datetime.now(), plc_id, tag_id, meta['area'], meta['db'], meta['addr'], value, dtype, 'write'
                    ))

                curr_d += 4 + byte_len
                if byte_len % 2 == 1: curr_d += 1  # Padding

        except:
            pass
        return variables

    def _handle_read_response(self, payload, data_start, tpdu_ref, plc_id):
        if tpdu_ref not in self.shadow_memory: return []
        req_items = self.shadow_memory.pop(tpdu_ref)
        variables = []
        curr_d = data_start

        try:
            for meta in req_items:
                if curr_d + 4 > len(payload): break

                ret_code = payload[curr_d]
                trans_size = payload[curr_d + 1]
                raw_len = struct.unpack('>H', payload[curr_d + 2:curr_d + 4])[0]

                byte_len = (raw_len + 7) // 8

                if ret_code == 0xFF:
                    val_start = curr_d + 4
                    raw_bytes = payload[val_start: val_start + byte_len]

                    tag_id, value, dtype = self._convert_value(meta['area'], meta['db'], meta['start'], raw_bytes)

                    if tag_id and value is not None:
                        variables.append(S7Variable(
                            datetime.now(), plc_id, tag_id, meta['area'], meta['db'], meta['start'], value, dtype,
                            'read'
                        ))

                curr_d += 4 + byte_len
                if byte_len % 2 == 1: curr_d += 1

        except:
            pass
        return variables

    def _convert_value(self, area, db, addr, raw_bytes):
        """
        核心修复：支持 I/Q/M/DB 区域，并根据字节长度自动适配类型
        """
        tag_id = None

        # 1. 标签 ID 生成 (支持所有常用区域)
        if area == 0x84:
            tag_id = f"DB{db}.DBD{addr}"  # DB
        elif area == 0x81:
            tag_id = f"I{addr}"  # Input
        elif area == 0x82:
            tag_id = f"Q{addr}"  # Output
        elif area == 0x83:
            tag_id = f"M{addr}"  # Merker (Flags)
        else:
            # 允许未知区域，记录为 RAW
            tag_id = f"Area{area}_{addr}"

        value = None
        dtype = "RAW"

        try:
            length = len(raw_bytes)

            # --- 4 字节: 可能是 Float 或 DWord ---
            if length == 4:
                # 只有 DB 块才优先尝试 Float (传感器数据通常在 DB)
                if area == 0x84:
                    f_val = struct.unpack('>f', raw_bytes)[0]
                    # 检查 Float 合理性 (-10亿 ~ 10亿)
                    if np.isfinite(f_val) and abs(f_val) < 1e9 and abs(f_val) > 1e-9:
                        value = round(f_val, 4)
                        dtype = "REAL"
                    elif raw_bytes == b'\x00\x00\x00\x00':
                        value = 0.0
                        dtype = "REAL"
                    else:
                        value = struct.unpack('>I', raw_bytes)[0]
                        dtype = "DWORD"
                else:
                    # I/Q/M 区如果是 4 字节，通常是 DINT/DWORD
                    value = struct.unpack('>I', raw_bytes)[0]
                    dtype = "DWORD"

            # --- 2 字节: Word / Int ---
            elif length == 2:
                value = struct.unpack('>H', raw_bytes)[0]
                dtype = "WORD"

            # --- 1 字节: Byte / Bool Group ---
            elif length == 1:
                value = raw_bytes[0]  # 直接转 int
                dtype = "BYTE"

            # --- 其他长度 ---
            else:
                # 尝试转为大整数或 hex 字符串
                if length > 0:
                    value = int.from_bytes(raw_bytes, byteorder='big')
                    dtype = f"BYTES_{length}"

        except Exception as e:
            return None, None, None

        return tag_id, value, dtype

# -------------------------------------------------------------------------
# Phase 2: Data Characterisation
# -------------------------------------------------------------------------

class DataCharacterisation:
    """变量特征化分类器"""

    def __init__(self, k: int = 3):
        self.k = k
        self.max_distinct_for_attribute = 2 ** k
        self.characteristics: Dict[str, VariableType] = {}

    def characterise_variables(self, variables: List[S7Variable]) -> Dict[str, VariableType]:
        var_observations = defaultdict(list)
        for var in variables:
            if var.value is not None and (isinstance(var.value, (int, float)) and np.isfinite(var.value)):
                var_observations[var.tag_id].append(var.value)

        classifications = {}
        for tag_id, values in var_observations.items():
            distinct_values = set()
            for val in values:
                if isinstance(val, float):
                    distinct_values.add(round(val, 2))
                else:
                    distinct_values.add(val)

            num_distinct = len(distinct_values)
            if num_distinct == 1:
                var_type = VariableType.CONSTANT
            elif num_distinct <= self.max_distinct_for_attribute:
                var_type = VariableType.ATTRIBUTE
            else:
                var_type = VariableType.CONTINUOUS

            self.characteristics[tag_id] = var_type
            classifications[tag_id] = var_type

        return classifications

    def print_statistics(self):
        type_counts = Counter(self.characteristics.values())
        logger.info("Classification Stats: " + str(dict(type_counts)))


# -------------------------------------------------------------------------
# Phase 3: Modelling & Detection Engine
# -------------------------------------------------------------------------

class MultiModelDetector:
    """多模型检测引擎"""

    def __init__(self, ar_lag: int = 5, f_test_window: int = 10, significance_level: float = 0.0005):
        self.ar_lag = ar_lag
        self.f_test_window = f_test_window
        self.alpha = significance_level
        self.models: Dict[str, VariableModel] = {}
        self.alerts: List[DetectionAlert] = []

    def train_models(self, variables: List[S7Variable], classifications: Dict[str, VariableType]):
        var_data = defaultdict(list)
        for var in variables:
            if var.value is not None: var_data[var.tag_id].append(var.value)

        for tag_id, var_type in classifications.items():
            values = var_data[tag_id]
            model = VariableModel(tag_id=tag_id, var_type=var_type)

            if var_type == VariableType.CONSTANT:
                model.expected_values = set(values)
            elif var_type == VariableType.ATTRIBUTE:
                model.enumeration_set = set(values)
            elif var_type == VariableType.CONTINUOUS:
                try:
                    series = np.array(values, dtype=float)
                    if len(series) > self.ar_lag * 3:
                        ar = AutoReg(series, lags=self.ar_lag).fit()
                        model.ar_model = ar
                        model.train_variance = np.var(ar.resid)
                        mean, std = np.mean(series), np.std(series)
                        model.control_limits = (mean - 3 * std, mean + 3 * std)
                except:
                    pass

            self.models[tag_id] = model

    def detect(self, var: S7Variable) -> Optional[DetectionAlert]:
        if var.tag_id not in self.models: return None
        model = self.models[var.tag_id]
        val = var.value

        if model.var_type == VariableType.CONSTANT:
            if val not in model.expected_values:
                return self._create_alert(var, "CONSTANT_CHANGE", model.expected_values, val, "CRITICAL")

        elif model.var_type == VariableType.ATTRIBUTE:
            if val not in model.enumeration_set:
                return self._create_alert(var, "ATTRIBUTE_UNKNOWN", model.enumeration_set, val, "WARNING")

        elif model.var_type == VariableType.CONTINUOUS:
            # 1. Control Limits
            l_min, l_max = model.control_limits
            if val < l_min or val > l_max:
                return self._create_alert(var, "LIMIT_VIOLATION", f"[{l_min:.2f},{l_max:.2f}]", val, "WARNING")

            # 2. AR Logic
            if model.ar_model and len(model.history) == self.ar_lag:
                params = model.ar_model.params
                pred = params[0]
                for i in range(self.ar_lag): pred += params[i + 1] * model.history[-(i + 1)]

                resid = val - pred
                model.residual_window.append(resid)

                if len(model.residual_window) == self.f_test_window:
                    curr_var = np.var(model.residual_window)
                    f_stat = curr_var / (model.train_variance if model.train_variance > 0 else 1e-6)
                    crit = f.ppf(1 - self.alpha, self.f_test_window - 1, 5000)

                    if f_stat > crit:
                        return self._create_alert(var, "PROCESS_ANOMALY", f"Pred:{pred:.2f}", val, "CRITICAL")

            model.history.append(val)
        return None

    def _create_alert(self, var, atype, exp, obs, sev):
        alert = DetectionAlert(var.timestamp, var.tag_id, atype, sev, exp, obs, "Anomaly detected")
        self.alerts.append(alert)
        return alert

    def get_alert_summary(self):
        return {'total': len(self.alerts)}


# -------------------------------------------------------------------------
# Main System
# -------------------------------------------------------------------------

class IndustrialS7Monitor:
    def __init__(self, interface="lo"):
        self.interface = interface
        self.extractor = S7DataExtractor()
        self.characteriser = DataCharacterisation()
        self.detector = MultiModelDetector()
        self.trained = False

    def train_from_pcap(self, path):
        if not os.path.exists(path): return
        logger.info(f"Training from {path}...")

        with PcapReader(path) as reader:
            for pkt in reader:
                self.extractor.parse_packet(pkt)

        classifications = self.characteriser.characterise_variables(self.extractor.variables_extracted)
        self.characteriser.print_statistics()
        self.detector.train_models(self.extractor.variables_extracted, classifications)
        self.trained = True
        logger.info("Training Complete.")

    def start_live_monitor(self):
        if not self.trained:
            logger.error("Not trained!")
            return

        logger.info(f"Monitoring {self.interface} for TCP port 102...")

        def handler(pkt):
            vars_ = self.extractor.parse_packet(pkt)
            for v in vars_:
                alert = self.detector.detect(v)
                if alert: self._print_alert(alert)

        sniff(iface=self.interface, filter="tcp port 102", prn=handler, store=0)

    def _print_alert(self, alert):
        logger.warning(
            f"[{alert.severity}] {alert.alert_type} @ {alert.tag_id}: Obs={alert.observed}, Exp={alert.expected}")


# -------------------------------------------------------------------------
# Entry Point
# -------------------------------------------------------------------------
if __name__ == "__main__":
    monitor = IndustrialS7Monitor(interface="lo")  # Change interface as needed

    # Generate dummy pcap if needed or verify files
    if not os.path.exists("train.pcap"):
        logger.info("Please provide train.pcap for baseline training.")
    else:
        monitor.train_from_pcap("train.pcap")

        # Uncomment to run live
        # monitor.start_live_monitor()

        # Or parse test pcap offline
        if os.path.exists("test.pcap"):
            logger.info("Testing on test.pcap...")
            with PcapReader("test.pcap") as reader:
                for pkt in reader:
                    vars_ = monitor.extractor.parse_packet(pkt)
                    for v in vars_:
                        alert = monitor.detector.detect(v)
                        if alert: monitor._print_alert(alert)