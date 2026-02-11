#!/usr/bin/env python3
"""
S7comm Industrial Security Monitor - Wireshark Style Edition
Features:
1. Frame Number Tracking (Matches Wireshark left column)
2. Robust S7 Parsing (Supports DB/I/Q/M areas)
3. Three-Phase Detection (Constant/Attribute/Continuous)
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

# Statistics
from scipy.stats import f
from statsmodels.tsa.ar_model import AutoReg

# Scapy
from scapy.all import sniff, PcapReader, TCP, IP, Raw

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(message)s',  # Simplified format to highlight Frame info
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("S7-Monitor")
warnings.filterwarnings("ignore")


# -------------------------------------------------------------------------
# Data Structures
# -------------------------------------------------------------------------

class VariableType(Enum):
    CONSTANT = "constant"
    ATTRIBUTE = "attribute"
    CONTINUOUS = "continuous"


@dataclass
class S7Variable:
    """S7变量对象 (Added frame_num)"""
    timestamp: datetime
    frame_num: int  # <--- 新增：Wireshark 编号
    plc_id: str
    tag_id: str
    area: int
    db_number: int
    address: int
    value: Any
    data_type: str
    operation: str


@dataclass
class VariableModel:
    tag_id: str
    var_type: VariableType
    expected_values: Set[Any] = field(default_factory=set)
    enumeration_set: Set[Any] = field(default_factory=set)
    ar_model: Optional[Any] = None
    control_limits: Tuple[float, float] = (0, 0)
    train_variance: float = 0
    history: deque = field(default_factory=lambda: deque(maxlen=5))
    residual_window: deque = field(default_factory=lambda: deque(maxlen=10))


@dataclass
class DetectionAlert:
    """检测告警 (Added frame_num)"""
    timestamp: datetime
    frame_num: int  # <--- 新增
    tag_id: str
    alert_type: str
    severity: str
    expected: Any
    observed: Any
    details: str


# -------------------------------------------------------------------------
# Phase 1: Data Extraction (With Frame Counter)
# -------------------------------------------------------------------------

class S7DataExtractor:
    def __init__(self):
        self.shadow_memory: Dict[int, List[Dict]] = {}
        self.variables_extracted: List[S7Variable] = []

    def parse_packet(self, pkt, frame_num: int) -> List[S7Variable]:
        """
        解析函数现在接收 frame_num 参数
        """
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return []

        payload = bytes(pkt[Raw].load)

        # 智能寻找 S7 Header (0x32)
        s7_offset = -1
        if len(payload) > 5 and payload[0] == 0x03:
            cotp_len = payload[4]
            calc_offset = 5 + cotp_len
            if calc_offset < len(payload) and payload[calc_offset] == 0x32:
                s7_offset = calc_offset

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
            ts = datetime.fromtimestamp(float(pkt.time))

            # Job Request (Write)
            if rosctr == 1:
                func = payload[param_start]
                if func == 0x05:
                    vars_ = self._handle_write_request(payload, param_start, data_start, plc_id, ts, frame_num)
                    variables.extend(vars_)
                elif func == 0x04:
                    self._handle_read_request(payload, param_start, tpdu_ref)

            # Ack_Data (Read)
            elif rosctr == 3:
                error_class = payload[s7_offset + 10]
                if error_class == 0:
                    vars_ = self._handle_read_response(payload, data_start, tpdu_ref, plc_id, ts, frame_num)
                    variables.extend(vars_)

        except Exception as e:
            pass

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
                items.append({'area': area, 'db': db, 'start': addr_raw >> 3, 'len': len_})
                curr += 12
            if items:
                self.shadow_memory[tpdu_ref] = items
        except:
            pass

    def _handle_write_request(self, payload, param_start, data_start, plc_id, ts, frame_num):
        variables = []
        try:
            item_count = payload[param_start + 1]
            # 1. Parameter
            items_meta = []
            curr_p = param_start + 2
            for _ in range(item_count):
                len_ = struct.unpack('>H', payload[curr_p + 4:curr_p + 6])[0]
                db = struct.unpack('>H', payload[curr_p + 6:curr_p + 8])[0]
                area = payload[curr_p + 8]
                addr_raw = (payload[curr_p + 9] << 16) | (payload[curr_p + 10] << 8) | payload[curr_p + 11]
                items_meta.append({'area': area, 'db': db, 'addr': addr_raw >> 3, 'len': len_})
                curr_p += 12

            # 2. Data
            curr_d = data_start
            for meta in items_meta:
                if curr_d + 4 > len(payload): break

                trans_size = payload[curr_d + 1]
                raw_len = struct.unpack('>H', payload[curr_d + 2:curr_d + 4])[0]

                if trans_size in [0x03, 0x04, 0x05]:
                    byte_len = (raw_len + 7) // 8
                else:
                    byte_len = raw_len

                val_start = curr_d + 4
                raw_bytes = payload[val_start: val_start + byte_len]

                tag_id, value, dtype = self._convert_value(meta['area'], meta['db'], meta['addr'], raw_bytes)

                if tag_id and value is not None:
                    variables.append(S7Variable(
                        ts, frame_num, plc_id, tag_id, meta['area'], meta['db'], meta['addr'], value, dtype, 'write'
                    ))

                curr_d += 4 + byte_len
                if byte_len % 2 == 1: curr_d += 1

        except:
            pass
        return variables

    def _handle_read_response(self, payload, data_start, tpdu_ref, plc_id, ts, frame_num):
        if tpdu_ref not in self.shadow_memory: return []
        req_items = self.shadow_memory.pop(tpdu_ref)
        variables = []
        curr_d = data_start

        try:
            for meta in req_items:
                if curr_d + 4 > len(payload): break

                ret_code = payload[curr_d]
                raw_len = struct.unpack('>H', payload[curr_d + 2:curr_d + 4])[0]
                byte_len = (raw_len + 7) // 8

                if ret_code == 0xFF:
                    val_start = curr_d + 4
                    raw_bytes = payload[val_start: val_start + byte_len]

                    tag_id, value, dtype = self._convert_value(meta['area'], meta['db'], meta['start'], raw_bytes)
                    if tag_id and value is not None:
                        variables.append(S7Variable(
                            ts, frame_num, plc_id, tag_id, meta['area'], meta['db'], meta['start'], value, dtype, 'read'
                        ))

                curr_d += 4 + byte_len
                if byte_len % 2 == 1: curr_d += 1

        except:
            pass
        return variables

    def _convert_value(self, area, db, addr, raw_bytes):
        tag_id = None
        if area == 0x84:
            tag_id = f"DB{db}.DBD{addr}"
        elif area == 0x81:
            tag_id = f"I{addr}"
        elif area == 0x82:
            tag_id = f"Q{addr}"
        elif area == 0x83:
            tag_id = f"M{addr}"
        else:
            tag_id = f"Area{area}_{addr}"

        value = None
        dtype = "RAW"
        try:
            length = len(raw_bytes)
            if length == 4:
                if area == 0x84:
                    f_val = struct.unpack('>f', raw_bytes)[0]
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
                    value = struct.unpack('>I', raw_bytes)[0]
                    dtype = "DWORD"
            elif length == 2:
                value = struct.unpack('>H', raw_bytes)[0]
                dtype = "WORD"
            elif length == 1:
                value = raw_bytes[0]
                dtype = "BYTE"
        except:
            return None, None, None
        return tag_id, value, dtype


# -------------------------------------------------------------------------
# Phase 2 & 3: Characterisation & Detection
# -------------------------------------------------------------------------

class DataCharacterisation:
    def __init__(self, k: int = 3):
        self.k = k
        self.max_distinct = 2 ** k
        self.characteristics: Dict[str, VariableType] = {}

    def characterise_variables(self, variables: List[S7Variable]) -> Dict[str, VariableType]:
        var_obs = defaultdict(list)
        for var in variables:
            if var.value is not None: var_obs[var.tag_id].append(var.value)

        classifications = {}
        for tag_id, values in var_obs.items():
            distinct = set()
            for v in values:
                if isinstance(v, float):
                    distinct.add(round(v, 2))
                else:
                    distinct.add(v)

            if len(distinct) == 1:
                vtype = VariableType.CONSTANT
            elif len(distinct) <= self.max_distinct:
                vtype = VariableType.ATTRIBUTE
            else:
                vtype = VariableType.CONTINUOUS

            self.characteristics[tag_id] = vtype
            classifications[tag_id] = vtype
        return classifications

    def print_stats(self):
        logger.info(f"[STATS] Variable Types: {dict(Counter(self.characteristics.values()))}")


class MultiModelDetector:
    def __init__(self, ar_lag=5, f_win=10, alpha=0.0005):
        self.ar_lag = ar_lag
        self.f_win = f_win
        self.alpha = alpha
        self.models = {}
        self.alerts = []

    def train_models(self, variables, classifications):
        var_data = defaultdict(list)
        for var in variables: var_data[var.tag_id].append(var.value)

        for tag, vtype in classifications.items():
            vals = var_data[tag]
            model = VariableModel(tag, vtype)

            if vtype == VariableType.CONSTANT:
                model.expected_values = set(vals)
            elif vtype == VariableType.ATTRIBUTE:
                model.enumeration_set = set(vals)
            elif vtype == VariableType.CONTINUOUS:
                try:
                    s = np.array(vals, dtype=float)
                    if len(s) > self.ar_lag * 3:
                        ar = AutoReg(s, lags=self.ar_lag).fit()
                        model.ar_model = ar
                        model.train_variance = np.var(ar.resid)
                        mean, std = np.mean(s), np.std(s)
                        model.control_limits = (mean - 3 * std, mean + 3 * std)
                except:
                    pass
            self.models[tag] = model

    def detect(self, var: S7Variable) -> Optional[DetectionAlert]:
        if var.tag_id not in self.models: return None
        model = self.models[var.tag_id]
        val = var.value

        # Constant
        if model.var_type == VariableType.CONSTANT:
            if val not in model.expected_values:
                return self._alert(var, "CONST_CHG", model.expected_values, val, "CRITICAL")

        # Attribute
        elif model.var_type == VariableType.ATTRIBUTE:
            if val not in model.enumeration_set:
                return self._alert(var, "ATTR_UNKNOWN", model.enumeration_set, val, "WARNING")

        # Continuous
        elif model.var_type == VariableType.CONTINUOUS:
            l_min, l_max = model.control_limits
            if val < l_min or val > l_max:
                return self._alert(var, "LIMIT_FAIL", f"[{l_min:.2f},{l_max:.2f}]", val, "WARNING")

            if model.ar_model and len(model.history) == self.ar_lag:
                params = model.ar_model.params
                pred = params[0]
                for i in range(self.ar_lag): pred += params[i + 1] * model.history[-(i + 1)]

                model.residual_window.append(val - pred)

                if len(model.residual_window) == self.f_win:
                    curr_var = np.var(model.residual_window)
                    f_stat = curr_var / (model.train_variance if model.train_variance > 0 else 1e-6)
                    crit = f.ppf(1 - self.alpha, self.f_win - 1, 5000)

                    if f_stat > crit:
                        return self._alert(var, "AR_ANOMALY", f"Pred:{pred:.2f}", val, "CRITICAL")

            model.history.append(val)
        return None

    def _alert(self, var, atype, exp, obs, sev):
        alert = DetectionAlert(var.timestamp, var.frame_num, var.tag_id, atype, sev, exp, obs, "Anomaly")
        self.alerts.append(alert)
        return alert


# -------------------------------------------------------------------------
# Main Monitor
# -------------------------------------------------------------------------

class IndustrialS7Monitor:
    def __init__(self, interface="lo"):
        self.interface = interface
        self.extractor = S7DataExtractor()
        self.characteriser = DataCharacterisation()
        self.detector = MultiModelDetector()
        self.trained = False
        self.live_packet_count = 0  # 实时监控计数器

    def train_from_pcap(self, path):
        if not os.path.exists(path): return
        logger.info(f"Training from {path}...")

        with PcapReader(path) as reader:
            # 使用 enumerate 生成包编号，从1开始
            for i, pkt in enumerate(reader, start=1):
                self.extractor.parse_packet(pkt, frame_num=i)

        classifications = self.characteriser.characterise_variables(self.extractor.variables_extracted)
        self.characteriser.print_stats()
        self.detector.train_models(self.extractor.variables_extracted, classifications)
        self.trained = True
        logger.info("Training Complete.")

    def start_live_monitor(self):
        if not self.trained: return
        logger.info(f"Monitoring {self.interface} for TCP port 102...")

        self.live_packet_count = 0  # 重置计数

        def handler(pkt):
            self.live_packet_count += 1
            # 传入计数器作为 frame_num
            vars_ = self.extractor.parse_packet(pkt, frame_num=self.live_packet_count)
            for v in vars_:
                alert = self.detector.detect(v)
                if alert: self._print_alert(alert)

        sniff(iface=self.interface, filter="tcp port 102", prn=handler, store=0)

    def detect_offline(self, path):
        if not os.path.exists(path): return
        logger.info(f"Testing on {path}...")
        with PcapReader(path) as reader:
            for i, pkt in enumerate(reader, start=1):
                vars_ = self.extractor.parse_packet(pkt, frame_num=i)
                for v in vars_:
                    alert = self.detector.detect(v)
                    if alert: self._print_alert(alert)

    def _print_alert(self, alert):
        # 格式化输出，带包编号
        logger.warning(
            f"[{alert.severity}] [Frame #{alert.frame_num}] {alert.alert_type} @ {alert.tag_id}: "
            f"Obs={alert.observed}, Exp={alert.expected}"
        )


if __name__ == "__main__":
    monitor = IndustrialS7Monitor(interface="lo")

    if os.path.exists("train.pcap"):
        monitor.train_from_pcap("train.pcap")

        if os.path.exists("test.pcap"):
            monitor.detect_offline("test.pcap")