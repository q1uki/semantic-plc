#!/usr/bin/env python3


import logging
import warnings
import os
import struct
import numpy as np
import pickle  # Added for model persistence
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple, Optional, Set, Any

# Statistics
from scipy.stats import f as f_dist

# Scapy
from scapy.all import sniff, PcapReader, TCP, IP, Raw

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("S7-Monitor-Refactored")
warnings.filterwarnings("ignore")


# -------------------------------------------------------------------------
# Algorithms: Burg's Method
# -------------------------------------------------------------------------

def ar_burg(x: np.ndarray, order: int) -> Tuple[np.ndarray, float]:
    """
    Estimate AR coefficients using Burg's method.
    """
    N = len(x)
    if N < order + 2:
        raise ValueError(f"样本量 {N} 不足以估计 AR({order})")
    fwd = x.astype(float).copy()
    bwd = x.astype(float).copy()
    a = np.zeros(0)
    sigma2 = float(np.dot(x, x) / N)

    for k in range(1, order + 1):
        f1 = fwd[1:]
        b0 = bwd[:-1]

        numer = -2.0 * np.dot(f1, b0)
        denom = np.dot(f1, f1) + np.dot(b0, b0)

        mu = 0.0 if denom == 0 else float(numer / denom)
        mu = float(np.clip(mu, -1 + 1e-9, 1 - 1e-9))

        # levinson-durbin
        if len(a) > 0:
            a = a + mu * a[::-1]
        a = np.append(a, mu)

        fwd = f1 + mu * b0
        bwd = b0 + mu * f1
        sigma2 *= (1.0 - mu ** 2)

    return a, max(float(sigma2), 1e-12)

# =========================================================================
# 阶数选择：AIC
# 原文: "To estimate the order of the model, we use the common
#        Akaike information criterion [34]"
# 参考: Sugiura (1978), Communications in Statistics
#
# 标准 AIC = N * ln(σ²) + 2 * (自由参数数)
# AR(p) 模型在去均值后，自由参数为 p 个系数。
# =========================================================================

def aic_ar(N: int, sigma2: float, p: int) -> float:
    if sigma2 <= 0:
        return float('inf')
    return N * np.log(sigma2) + 2 * p

# -------------------------------------------------------------------------
# Data Structures
# -------------------------------------------------------------------------

class VariableType(Enum):
    CONSTANT = "constant"
    ATTRIBUTE = "attribute"
    CONTINUOUS = "continuous"


@dataclass
class S7Variable:
    timestamp: float
    frame_num: int
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

    # Constant/Attribute Models
    expected_values: Set[Any] = field(default_factory=set)
    enumeration_set: Set[Any] = field(default_factory=set)

    # Continuous Models (AR + Control Limits)
    ar_model_params: Optional[np.ndarray] = None
    ar_lag_p: int = 0
    ar_mean: float = 0.0
    control_limits: Tuple[float, float] = (0.0, 0.0)

    # Detection State
    train_residual_variance: float = 0.0
    history_buffer: deque = field(default_factory=lambda: deque(maxlen=50))
    prediction_errors: deque = field(default_factory=lambda: deque(maxlen=30))
    last_seen_time: float = 0.0
    last_seen_value: float = 0.0

    # ------------------------------------------------------------------
    # Warmup 机制
    # 论文使用 rolling forecasting（训练集与测试集紧接），
    # 在真实部署场景中训练结束到上线之间存在时间差，
    # 必须先用真实在线数据重新填充 history_buffer，
    # 而不是使用可能已过时的训练集末尾值。
    #
    # warmup_n    : 开始真正检测前需要积累的在线观测数量。
    #               未被论文规定，由调用方根据轮询频率设定。
    #               例：轮询周期~2s，warmup_n=30 ≈ 1分钟的缓冲。
    # warmup_done : True 后不再修改，进入正式检测模式。
    # warmup_count: 已累积的在线观测计数。
    # ------------------------------------------------------------------
    warmup_n: int = 30
    warmup_done: bool = False
    warmup_count: int = 0


@dataclass
class DetectionAlert:
    timestamp: float
    frame_num: int
    tag_id: str
    alert_type: str
    severity: str
    expected: Any
    observed: Any
    details: str


# -------------------------------------------------------------------------
# Phase 1: Data Extraction (protocol parse, shadow memory)
# -------------------------------------------------------------------------

class S7DataExtractor:
    def __init__(self):
        self.shadow_memory: Dict[int, List[Dict]] = {}
        self.variables_extracted: List[S7Variable] = []

    def parse_packet(self, pkt, frame_num: int) -> List[S7Variable]:
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return []

        if pkt[TCP].dport != 102 and pkt[TCP].sport != 102:
            return []

        payload = bytes(pkt[Raw].load)
        if len(payload) < 4 or payload[0] != 0x03:
            return []

        try:
            cotp_len = payload[4]
            s7_offset = 5 + cotp_len
            if s7_offset >= len(payload) or payload[s7_offset] != 0x32:
                return []
        except IndexError:
            return []

        variables = []
        try:
            rosctr = payload[s7_offset + 1]
            tpdu_ref = struct.unpack('>H', payload[s7_offset + 4: s7_offset + 6])[0]
            param_len = struct.unpack('>H', payload[s7_offset + 6: s7_offset + 8])[0]

            header_len = 12 if rosctr == 3 else 10
            param_start = s7_offset + header_len
            data_start = param_start + param_len

            plc_id = pkt[IP].src if pkt.haslayer(IP) else "unknown"
            ts = float(pkt.time)

            if rosctr == 1:  # Job
                func = payload[param_start]
                if func == 0x05:  # Write Var
                    vars_ = self._handle_write_request(payload, param_start, data_start, plc_id, ts, frame_num)
                    variables.extend(vars_)
                elif func == 0x04:  # Read Var
                    self._handle_read_request(payload, param_start, tpdu_ref)

            elif rosctr == 3:  # Ack_Data
                error_class = payload[s7_offset + 10]
                if error_class == 0:
                    vars_ = self._handle_read_response(payload, data_start, tpdu_ref, plc_id, ts, frame_num)
                    variables.extend(vars_)
        except Exception:
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
            items_meta = []
            curr_p = param_start + 2

            for _ in range(item_count):
                len_ = struct.unpack('>H', payload[curr_p + 4:curr_p + 6])[0]
                db = struct.unpack('>H', payload[curr_p + 6:curr_p + 8])[0]
                area = payload[curr_p + 8]
                addr_raw = (payload[curr_p + 9] << 16) | (payload[curr_p + 10] << 8) | payload[curr_p + 11]
                items_meta.append({'area': area, 'db': db, 'addr': addr_raw >> 3, 'len': len_})
                curr_p += 12

            curr_d = data_start
            for meta in items_meta:
                if curr_d + 4 > len(payload): break
                raw_len = struct.unpack('>H', payload[curr_d + 2:curr_d + 4])[0]
                byte_len = raw_len // 8 if payload[curr_d + 1] in [0x03, 0x04, 0x05] else raw_len
                if byte_len == 0 and raw_len > 0: byte_len = raw_len

                val_start = curr_d + 4
                raw_bytes = payload[val_start: val_start + byte_len]

                for tag_id, addr, value, dtype in self._extract_variables(meta['area'], meta['db'], meta['addr'], raw_bytes):
                    variables.append(S7Variable(ts, frame_num, plc_id, tag_id, meta['area'], meta['db'], addr, value, dtype, 'write'))

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
                byte_len = raw_len // 8
                if byte_len == 0: byte_len = raw_len

                if ret_code == 0xFF:
                    val_start = curr_d + 4
                    raw_bytes = payload[val_start: val_start + byte_len]
                    for tag_id, addr, value, dtype in self._extract_variables(meta['area'], meta['db'], meta['start'], raw_bytes):
                        variables.append(S7Variable(ts, frame_num, plc_id, tag_id, meta['area'], meta['db'], addr, value, dtype, 'read'))

                curr_d += 4 + byte_len
                if byte_len % 2 == 1: curr_d += 1
        except:
            pass
        return variables

    def _extract_variables(self, area, db, base_addr, raw_bytes):
        extracted = []
        length = len(raw_bytes)

        if area == 0x84:
            prefix = f"DB{db}.DB"
        elif area == 0x81:
            prefix = "I"
        elif area == 0x82:
            prefix = "Q"
        elif area == 0x83:
            prefix = "M"
        else:
            prefix = f"Area{area}_"

        if length == 1:
            tag_id = f"{prefix}B{base_addr}" if area == 0x84 else f"{prefix}{base_addr}"
            extracted.append((tag_id, base_addr, raw_bytes[0], "BYTE"))
        elif length == 2:
            tag_id = f"{prefix}W{base_addr}"
            val = struct.unpack('>h', raw_bytes)[0]
            extracted.append((tag_id, base_addr, val, "INT"))
        elif length == 4:
            tag_id = f"{prefix}D{base_addr}"
            f_val = struct.unpack('>f', raw_bytes)[0]
            if np.isfinite(f_val) and 1e-9 < abs(f_val) < 1e9:
                extracted.append((tag_id, base_addr, round(f_val, 4), "REAL"))
            else:
                val = struct.unpack('>i', raw_bytes)[0]
                extracted.append((tag_id, base_addr, val, "DINT"))
        elif length > 4:
            i = 0
            while i < length:
                curr_addr = base_addr + i
                if curr_addr >= 100 and (length - i) >= 2:
                    tag_id = f"{prefix}W{curr_addr}"
                    val = struct.unpack('>h', raw_bytes[i:i + 2])[0]
                    extracted.append((tag_id, curr_addr, val, "INT"))
                    i += 2
                else:
                    tag_id = f"{prefix}B{curr_addr}" if area == 0x84 else f"{prefix}{curr_addr}"
                    extracted.append((tag_id, curr_addr, raw_bytes[i], "BYTE"))
                    i += 1

        return extracted


# -------------------------------------------------------------------------
# Phase 2: Characterisation (Heuristics)
# -------------------------------------------------------------------------

class DataCharacterisation:
    def __init__(self, k: int = 3):
        self.k = k
        self.max_distinct = 2 ** k   # = 8

    def characterise_variables(self, variables: List[S7Variable]) -> Dict[str, VariableType]:
        var_obs: Dict[str, List] = defaultdict(list)
        for var in variables:
            if var.value is not None:
                var_obs[var.tag_id].append(var.value)

        classifications = {}
        for tag_id, values in var_obs.items():
            distinct = set(values)
            # [PAPER 3.4] 三分类规则
            if len(distinct) == 1:
                vtype = VariableType.CONSTANT
            elif len(distinct) <= self.max_distinct:
                vtype = VariableType.ATTRIBUTE
            else:
                vtype = VariableType.CONTINUOUS
            classifications[tag_id] = vtype

        return classifications

# -------------------------------------------------------------------------
# Phase 3: Modelling & Detection (AIC & Burg's Method)
# -------------------------------------------------------------------------
"""
    [PAPER §4] 论文明确规定的所有参数：

    1. AR系数估计：Burg法
    2. AR阶数选择：AIC
    3. 控制限：Shewhart，均值 ± 3σ
    4. 检测方法：两个F检验 (two variance hypothesis tests)
    5. 显著性水平：p = 0.05% = 0.0005（两个检验相同）

    [PAPER §3.5] 检测规则：
    - 常量/属性：值不在枚举集中则报警
    - 连续变量：(i) 超出控制限 OR (ii) AR预测偏差 → 报警

    [PAPER §3.5] AR偏差判断：
    "we compare the residual variance (observed during training) with
     the prediction error variance (observed during testing).
     A prediction error variance that is significantly higher than the
     residual variance implies that the real stream has deviated"
"""

class MultiModelDetector:
    # [PAPER §4] 论文原文: "we set p = 0.05% as their significance level"
    # p = 0.05% = 0.05/100 = 0.0005
    ALPHA: float = 0.0005

    # [IMPL] 默认 warmup 观测数量
    # 论文未规定此值（rolling forecasting 中不存在此问题）。
    # 对于轮询周期 ~2s 的工业现场，30个观测 ≈ 1分钟；
    # 对于更慢的轮询（~4s），建议提高到 60~90。
    DEFAULT_WARMUP_N: int = 30

    def __init__(self, alpha: float = ALPHA, warmup_n: int = DEFAULT_WARMUP_N):
        self.alpha = alpha
        self.warmup_n = warmup_n
        self.models: Dict[str, VariableModel] = {}
        self.alerts: List[DetectionAlert] = []

    def train_models(self, variables: List[S7Variable], classifications: Dict[str, VariableType]):
        """
                [PAPER §3.5] 对三类变量分别建立预测模型。

                连续变量建模步骤：
                1. 提取值序列（直接使用观测序列，无重采样）
                2. 计算 Shewhart 控制限：[μ-3σ, μ+3σ]
                3. 去均值（μ即论文公式中的 φ0）
                4. Burg法 + AIC 选最优AR阶数 p
                5. 保存 AR系数、均值、训练残差方差
        """
        var_data: Dict[str, Dict] = defaultdict(lambda: {'v': [], 't': []})
        for var in variables:
            var_data[var.tag_id]['t'].append(var.timestamp)
            var_data[var.tag_id]['v'].append(var.value)

        for tag, vtype in classifications.items():
            vals = [float(v) for v in var_data[tag]['v'] if v is not None]
            times = var_data[tag]['t']
            model = VariableModel(tag_id=tag, var_type=vtype, warmup_n=self.warmup_n)

            if vtype == VariableType.CONSTANT:
                model.expected_values = set(var_data[tag]['v'])

            elif vtype == VariableType.ATTRIBUTE:
                model.enumeration_set = set(var_data[tag]['v'])

            elif vtype == VariableType.CONTINUOUS:
                if not vals:
                    self.models[tag] = model
                    continue

                arr = np.array(vals)

                # [PAPER §3.5] Shewhart 控制限：μ ± 3σ
                # [IMPL] 使用无偏估计 ddof=1，符合 SPC 标准（参考文献[38]）
                mu = float(np.mean(arr))
                sigma = float(np.std(arr, ddof=1))
                model.control_limits = (mu - 3 * sigma, mu + 3 * sigma)

                # [PAPER §3.5] AR模型：去均值后拟合
                # [PAPER §4] Burg法 + AIC
                # [IMPL] 最小样本量=20（保证AIC有意义），最大搜索阶数=min(10, N//5)
                min_samples = 20
                if len(arr) > min_samples:
                    centered = arr - mu
                    model.ar_mean = mu

                    N = len(centered)
                    max_order = min(10, N // 5)

                    best_aic = float('inf')
                    best_p, best_params, best_var = 1, None, 0.0

                    for p in range(1, max_order + 1):
                        try:
                            coeffs, sigma2 = ar_burg(centered, p)
                            current_aic = aic_ar(N, sigma2, p)
                            if current_aic < best_aic:
                                best_aic = current_aic
                                best_p = p
                                best_params = coeffs
                                best_var = sigma2
                        except Exception:
                            continue

                    if best_params is not None:
                        model.ar_lag_p = best_p
                        model.ar_model_params = best_params
                        model.train_residual_variance = best_var
                        # [IMPL] 训练结束后 history_buffer 保持空，等待在线 warmup 阶段用真实数据填充。
                        logger.info(
                            f"[TRAIN] {tag}: AR({best_p}) | "
                            f"AIC={best_aic:.2f} | σ²_train={best_var:.6f} | "
                            f"warmup_n={model.warmup_n}"
                        )

                model.last_seen_value = vals[-1]
                model.last_seen_time = times[-1]

            self.models[tag] = model

        # ------------------------------------------------------------------
        # [PAPER §4] 两个F检验
        # "two variance hypothesis tests (commonly known as F-test).
        #  For both tests we set p = 0.05%"
        #
        # 根据论文引用的参考文献 [19] (Hoon 1995) 和 [38] (Wetherill & Brown 1991)：
        # Test 1（上侧）: 检测在线方差是否显著大于训练方差（过程漂移/攻击）
        # Test 2（下侧）: 检测训练方差是否显著大于在线方差（数据压缩/传感器故障）
        # 两个检验均使用 α = 0.0005
        # ------------------------------------------------------------------

    def _two_f_tests(self, model: VariableModel) -> Optional[str]:
        """
        返回:
          None       → 两个检验均未拒绝 H0，无异常
          "upper"    → Test 1 拒绝（在线方差显著偏高，过程偏离）
          "lower"    → Test 2 拒绝（在线方差显著偏低，异常平稳）
        """
        errors = np.array(list(model.prediction_errors))
        n = len(errors)
        if n < 5:
            return None

        # [IMPL] 在线方差估计使用无偏估计
        online_var = float(np.var(errors, ddof=1))
        train_var = max(model.train_residual_variance, 1e-12)

        # [IMPL] 训练集自由度设为 1000（大样本近似），与论文原始实现一致
        # 论文未明确说明训练集自由度，1000 是参考 Hoon(1995) 推荐的近似
        df_online = n - 1
        df_train = 1000

        # [PAPER §4] Test 1（上侧）：在线方差 >> 训练方差
        f_stat_upper = online_var / train_var
        crit_upper = f_dist.ppf(1 - self.alpha, df_online, df_train)
        if f_stat_upper > crit_upper:
            return "upper"

        # [PAPER §4] Test 2（下侧）：训练方差 >> 在线方差
        f_stat_lower = train_var / online_var
        crit_lower = f_dist.ppf(1 - self.alpha, df_train, df_online)
        if f_stat_lower > crit_lower:
            return "lower"

        return None

    def detect(self, var: S7Variable) -> Optional[DetectionAlert]:
        """
        [PAPER §3.5] 检测逻辑：

        常量：值不在 expected_values 中 → CRITICAL
        属性：值不在 enumeration_set 中 → WARNING
        连续：
          (i)  超出控制限 [Lmin, Lmax] → WARNING
          (ii) AR预测偏差（双F检验）→ CRITICAL/WARNING
        """
        if var.tag_id not in self.models: return None
        model = self.models[var.tag_id]
        val = var.value

        if model.var_type == VariableType.CONSTANT:
            if val not in model.expected_values:
                return self._alert(var, "CONST_CHG", model.expected_values, val, "CRITICAL","")

        elif model.var_type == VariableType.ATTRIBUTE:
            if val not in model.enumeration_set:
                return self._alert(var, "ATTR_UNKNOWN", model.enumeration_set, val, "WARNING","")


        # 连续变量检测

        elif model.var_type == VariableType.CONTINUOUS:

            val = float(val)
            # ----------------------------------------------------------
            # Warmup 阶段：history_buffer 用真实在线数据填充
            #
            # 设计依据：
            #   论文的 rolling forecasting 假设测试集紧接训练集，
            #   但实际部署中两者之间存在时间间隔。
            #   在 warmup 期间：
            #     - 控制限检测仍然运行（控制限只依赖均值/方差，不需要历史序列）
            #     - AR检测暂停（history_buffer 尚未充分填充在线数据）
            #     - 每个观测值都进入 history_buffer，建立真实的在线历史基础
            #
            # warmup 结束条件：累积到 warmup_n 个在线观测
            # ----------------------------------------------------------

            if not model.warmup_done:
                model.history_buffer.append(val)
                model.last_seen_time = var.timestamp
                model.last_seen_value = val
                model.warmup_count += 1

                if model.warmup_count >= model.warmup_n:
                    model.warmup_done = True
                    logger.info(
                        f"[WARMUP DONE] {var.tag_id}: "
                        f"已积累 {model.warmup_count} 个在线观测，开始正式检测"
                    )
                else:
                    # warmup 间只做控制限检测
                    l_min, l_max = model.control_limits
                    if val < l_min or val > l_max:
                        return self._alert(
                            var, "LIMIT_FAIL",
                            f"[{l_min:.4f}, {l_max:.4f}]", val,
                            "WARNING",
                            f"[Warmup {model.warmup_count}/{model.warmup_n}] "
                            f"超出Shewhart控制限"
                        )
                return None  # warmup 期间 AR 检测不运行

            # ----------------------------------------------------------
            # 正式检测阶段（warmup_done = True）
            # ----------------------------------------------------------

            # [PAPER §3.5] (i) 控制限检测
            l_min, l_max = model.control_limits
            if val < l_min or val > l_max:
                return self._alert(
                    var, "LIMIT_FAIL",
                    f"[{l_min:.4f}, {l_max:.4f}]", val,
                    "WARNING", "超出Shewhart控制限")

            # [PAPER §3.5] (ii) AR预测偏差检测
            if model.ar_model_params is not None and model.ar_lag_p > 0:
                p = model.ar_lag_p
                params = model.ar_model_params
                mu = model.ar_mean
                if len(model.history_buffer) >= p:
                    # 一步预测：xi_hat = μ + Σ φi*(x_{t-i} - μ)
                    hist = list(model.history_buffer)
                    pred_centered = sum(
                        params[i] * (hist[-(i + 1)] - mu)
                        for i in range(p)
                    )
                    pred = mu + pred_centered
                    residual = val - pred
                    model.prediction_errors.append(residual)

                    # [PAPER §4] 积累足够误差后运行双F检验
                    # [IMPL] 至少10个误差才开始检验，避免初始阶段假阳性
                    if len(model.prediction_errors) >= 10:
                        test_result = self._two_f_tests(model)
                        if test_result == "upper":
                            return self._alert(
                                var, "AR_ANOMALY_HIGH",
                                f"Pred:{pred:.4f}", val,
                                "CRITICAL",
                                f"在线预测误差方差显著高于训练基准 "
                                f"(σ²_online={np.var(list(model.prediction_errors), ddof=1):.4f} "
                                f"vs σ²_train={model.train_residual_variance:.4f})"
                            )

                        elif test_result == "lower":
                            return self._alert(
                                var, "AR_ANOMALY_LOW",
                                f"Pred:{pred:.4f}", val,
                                "WARNING",
                                "在线预测误差方差异常偏低（可能存在数据重放）"
                            )

            model.history_buffer.append(val)
            model.last_seen_time = var.timestamp
            model.last_seen_value = val

        return None

    def _alert(self, var: S7Variable, atype: str, expected: Any,
                    observed: Any, severity: str, details: str) -> DetectionAlert:
        alert = DetectionAlert(
            var.timestamp, var.frame_num, var.tag_id,
            atype, severity, expected, observed, details
        )
        self.alerts.append(alert)
        return alert

# -------------------------------------------------------------------------
# Main Monitor Execution
# -------------------------------------------------------------------------

class IndustrialS7Monitor:
    def __init__(self, interface: str = "lo",
                 warmup_n: int = MultiModelDetector.DEFAULT_WARMUP_N):
        self.interface = interface
        # [PAPER §4] k=3
        self.extractor = S7DataExtractor()
        self.characteriser = DataCharacterisation(k=3)
        # [PAPER §4] α=0.0005
        # [IMPL] warmup_n: 每个连续变量在开始AR检测前需积累的在线观测数量
        self.detector = MultiModelDetector(
            alpha=MultiModelDetector.ALPHA,
            warmup_n=warmup_n
        )
        self.trained = False
        self.live_packet_count = 0

    def save_model(self, filename="s7_model.pkl"):
        """Save the trained detector models to a file."""
        if not self.trained:
            logger.warning("Models not trained, nothing to save.")
            return

        try:
            with open(filename, 'wb') as f:
                pickle.dump(self.detector.models, f)
            logger.info(f"Models saved successfully to {filename}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def load_model(self, filename="s7_model.pkl") -> bool:
        """Load trained models from a file."""
        if not os.path.exists(filename):
            return False

        try:
            with open(filename, 'rb') as f:
                self.detector.models = pickle.load(f)
            self.trained = True
            logger.info(f"Models loaded successfully from {filename}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    def train_from_pcap(self, path):
        if not os.path.exists(path): return
        logger.info(f"Training from {path}...")

        with PcapReader(path) as reader:
            for i, pkt in enumerate(reader, start=1):
                self.extractor.parse_packet(pkt, frame_num=i)

        classifications = self.characteriser.characterise_variables(self.extractor.variables_extracted)
        self.detector.train_models(self.extractor.variables_extracted, classifications)
        self.trained = True
        logger.info("Training Complete.")

    def print_learned_rules(self):
        """
        Outputs the rules derived from the training phase for inspection.
        """
        if not self.trained:
            logger.warning("Models not trained yet.")
            return

        print("\n" + "=" * 80)
        print(f"{'LEARNED PROCESS RULES (SEMANTIC MODEL)':^80}")
        print("=" * 80)

        type_counts = {t: 0 for t in VariableType}
        # Sort by Tag ID for readability
        sorted_models = sorted(self.detector.models.items())

        for tag, model in sorted_models:
            type_counts[model.var_type] += 1
            print(f"[-] TAG: {tag:<20} | TYPE: {model.var_type.value.upper()}")

            if model.var_type == VariableType.CONSTANT:
                print(f"    Expected Value(s) : {model.expected_values}")

            elif model.var_type == VariableType.ATTRIBUTE:
                print(f"    Valid Enumeration : {model.enumeration_set}")

            elif model.var_type == VariableType.CONTINUOUS:
                l_min, l_max = model.control_limits
                print(f"    Control Limits    : [{l_min:.4f}, {l_max:.4f}]")
                if model.ar_model_params is not None:
                    coeffs = ", ".join([f"{c:.4f}" for c in model.ar_model_params])
                    print(f"    AR Model (Order p={model.ar_lag_p}):")
                    print(f"      Mean Value      : {model.ar_mean:.4f}")
                    print(f"      Coefficients    : [{coeffs}]")
                    print(f"      Residual Var    : {model.train_residual_variance:.6f}")
                else:
                    print("    AR Model          : Not converged or insufficient data for AR")
            print("-" * 80)
        print("\n")
        total = sum(type_counts.values())
        for t, cnt in type_counts.items():
            pct = 100 * cnt / total if total > 0 else 0
            print(f"  {t.value:12}: {cnt:4} 个 ({pct:.1f}%)")
        # [PAPER §5.2] 论文水厂数据: 常量约95.5%，属性1.4%，连续3.1%
        print("  (论文水厂基准: 常量≈95.5%, 属性≈1.4%, 连续≈3.1%)")
        print("=" * 90 + "\n")

    def start_live_monitor(self):
        if not self.trained: return
        logger.info(f"Monitoring {self.interface} for TCP port 102...")
        self.live_packet_count = 0

        def handler(pkt):
            self.live_packet_count += 1
            vars_ = self.extractor.parse_packet(pkt, frame_num=self.live_packet_count)
            for v in vars_:
                alert = self.detector.detect(v)
                if alert: self._print_alert(alert)

        sniff(iface=self.interface, filter="tcp port 102", prn=handler, store=0)

    def detect_offline(self, path):
        if not os.path.exists(path): return
        logger.info(f"Testing on {path}...")
        self.detector.alerts = []
        with PcapReader(path) as reader:
            for i, pkt in enumerate(reader, start=1):
                vars_ = self.extractor.parse_packet(pkt, frame_num=i)
                for v in vars_:
                    alert = self.detector.detect(v)
                    if alert: self._print_alert(alert)

    def _print_alert(self, alert):
        logger.warning(
            f"[{alert.severity}] [Frame #{alert.frame_num}] {alert.alert_type} @ {alert.tag_id}: "
            f"Obs={alert.observed}, Exp={alert.expected}"
        )


if __name__ == "__main__":
    # Modify Interface Here
    # warmup_n 设定说明：
    #   若轮询周期 ~2s：warmup_n=30 ≈ 1分钟
    #   若轮询周期 ~4s：warmup_n=60 ≈ 4分钟（建议，覆盖1个完整过程周期）
    #   若有明确的过程周期信息（如水厂8小时班次），可设置更大的值
    monitor = IndustrialS7Monitor(interface="Ethernet 3", warmup_n=30)

    MODEL_FILE = "s7_model.pkl"
    PCAP_FILE = "tank train.pcap"

    # 1. Check if model exists
    if os.path.exists(MODEL_FILE):
        logger.info(f"Found existing model file: {MODEL_FILE}")
        if monitor.load_model(MODEL_FILE):
            logger.info("Skipping training (Using loaded model).")
        else:
            logger.warning("Failed to load existing model. Retraining...")
            monitor.train_from_pcap(PCAP_FILE)
            monitor.save_model(MODEL_FILE)
    else:
        logger.info("No existing model found. Training from PCAP...")
        monitor.train_from_pcap(PCAP_FILE)
        monitor.save_model(MODEL_FILE)

    # 2. Output Learned Rules
    monitor.print_learned_rules()

    # 3. Live Monitor (Optional)
    try:
        monitor.start_live_monitor()
    except KeyboardInterrupt:
        print("\n[STOP] Keyboard interrupt.")

    # 4. Offline Test (Optional)
    # if os.path.exists("test.pcap"):
    #     monitor.detect_offline("test.pcap")
