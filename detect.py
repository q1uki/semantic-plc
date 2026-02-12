#!/usr/bin/env python3
"""
S7comm Semantic Security Monitor - Refactored for Paper Compliance (Burg's Method)
Refactored to align with "Through the Eye of the PLC"
Changes:
1. Implemented Burg's Method for AR coefficient estimation.
2. Implemented AIC (Akaike Information Criterion) for AR order selection.
3. Added Time-Series Resampling (1Hz Zero-Order Hold) for correct AR modeling.
4. Enhanced S7 Heuristic Parsing for robust extraction.
5. Added Rule Export Functionality.
6. Added Model Persistence (Save/Load).
"""

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
from scipy.stats import f

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
    f = x.copy()
    b = x.copy()
    a = np.zeros(0)
    sigma2 = np.dot(x, x) / N

    for k in range(1, order + 1):
        numer = -2.0 * np.dot(f[k:], b[k - 1:N - 1])
        denom = np.dot(f[k:], f[k:]) + np.dot(b[k - 1:N - 1], b[k - 1:N - 1])

        if denom == 0:
            mu = 0
        else:
            mu = numer / denom

        if len(a) > 0:
            a_prev = a.copy()
            a = a_prev + mu * a_prev[::-1]

        a = np.append(a, mu)

        f_new = f[1:] + mu * b[:-1]
        b_new = b[:-1] + mu * f[1:]
        f = f_new
        b = b_new
        sigma2 = (1.0 - mu ** 2) * sigma2

    return a, sigma2


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
    history_buffer: deque = field(default_factory=lambda: deque(maxlen=20))
    prediction_errors: deque = field(default_factory=lambda: deque(maxlen=15))
    last_seen_time: float = 0.0
    last_seen_value: float = 0.0


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
# Phase 1: Data Extraction (Robust)
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

                tag_id, value, dtype = self._convert_value(meta['area'], meta['db'], meta['addr'], raw_bytes)
                if tag_id and value is not None:
                    variables.append(
                        S7Variable(ts, frame_num, plc_id, tag_id, meta['area'], meta['db'], meta['addr'], value, dtype,
                                   'write'))

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
                    tag_id, value, dtype = self._convert_value(meta['area'], meta['db'], meta['start'], raw_bytes)
                    if tag_id and value is not None:
                        variables.append(
                            S7Variable(ts, frame_num, plc_id, tag_id, meta['area'], meta['db'], meta['start'], value,
                                       dtype, 'read'))

                curr_d += 4 + byte_len
                if byte_len % 2 == 1: curr_d += 1
        except:
            pass
        return variables

    def _convert_value(self, area, db, addr, raw_bytes):
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
                f_val = struct.unpack('>f', raw_bytes)[0]
                if np.isfinite(f_val) and 1e-9 < abs(f_val) < 1e9:
                    value = round(f_val, 4)
                    dtype = "REAL"
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
# Phase 2: Characterisation (Heuristics)
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
            distinct = set(values)

            if len(distinct) == 1:
                vtype = VariableType.CONSTANT
            elif len(distinct) <= self.max_distinct:
                vtype = VariableType.ATTRIBUTE
            else:
                vtype = VariableType.CONTINUOUS

            self.characteristics[tag_id] = vtype
            classifications[tag_id] = vtype
        return classifications


# -------------------------------------------------------------------------
# Phase 3: Modelling & Detection (AIC & Burg's Method)
# -------------------------------------------------------------------------

class MultiModelDetector:
    def __init__(self, sampling_rate=1.0, alpha=0.001):
        self.sampling_rate = sampling_rate
        self.alpha = alpha
        self.models = {}
        self.alerts = []

    def _resample_series(self, times, values) -> np.ndarray:
        if not times: return np.array([])
        t_start = np.floor(min(times))
        t_end = np.ceil(max(times))

        grid = np.arange(t_start, t_end + self.sampling_rate, self.sampling_rate)
        resampled = np.zeros(len(grid))

        curr_val = values[0]
        v_idx = 0
        for i, t in enumerate(grid):
            while v_idx < len(times) - 1 and times[v_idx + 1] <= t:
                v_idx += 1
                curr_val = values[v_idx]
            resampled[i] = curr_val

        return resampled

    def train_models(self, variables: List[S7Variable], classifications: Dict[str, VariableType]):
        var_data = defaultdict(lambda: {'t': [], 'v': []})
        for var in variables:
            var_data[var.tag_id]['t'].append(var.timestamp)
            var_data[var.tag_id]['v'].append(var.value)

        for tag, vtype in classifications.items():
            vals = var_data[tag]['v']
            times = var_data[tag]['t']
            model = VariableModel(tag, vtype)

            if vtype == VariableType.CONSTANT:
                model.expected_values = set(vals)

            elif vtype == VariableType.ATTRIBUTE:
                model.enumeration_set = set(vals)

            elif vtype == VariableType.CONTINUOUS:
                ts_values = self._resample_series(times, vals)
                mean, std = np.mean(ts_values), np.std(ts_values)
                model.control_limits = (mean - 3 * std, mean + 3 * std)

                if len(ts_values) > 20:
                    ts_mean = np.mean(ts_values)
                    ts_centered = ts_values - ts_mean
                    model.ar_mean = ts_mean

                    best_aic = float('inf')
                    best_params = None
                    best_lag = 1
                    best_variance = 0.0

                    max_search = min(10, len(ts_values) // 5)
                    N = len(ts_centered)

                    for p in range(1, max_search + 1):
                        try:
                            coeffs, sigma2 = ar_burg(ts_centered, p)
                            if sigma2 <= 0: continue
                            aic = N * np.log(sigma2) + 2 * (p + 1)

                            if aic < best_aic:
                                best_aic = aic
                                best_lag = p
                                best_params = coeffs
                                best_variance = sigma2
                        except:
                            continue

                    if best_params is not None:
                        model.ar_lag_p = best_lag
                        model.ar_model_params = best_params
                        model.train_residual_variance = best_variance
                        logger.info(f"Model {tag}: AR({best_lag}) via Burg/AIC. Var={best_variance:.4f}")

                model.last_seen_value = vals[-1] if vals else 0
                model.last_seen_time = times[-1] if times else 0

            self.models[tag] = model

    def detect(self, var: S7Variable) -> Optional[DetectionAlert]:
        if var.tag_id not in self.models: return None
        model = self.models[var.tag_id]
        val = var.value

        if model.var_type == VariableType.CONSTANT:
            if val not in model.expected_values:
                return self._alert(var, "CONST_CHG", model.expected_values, val, "CRITICAL")

        elif model.var_type == VariableType.ATTRIBUTE:
            if val not in model.enumeration_set:
                return self._alert(var, "ATTR_UNKNOWN", model.enumeration_set, val, "WARNING")

        elif model.var_type == VariableType.CONTINUOUS:
            l_min, l_max = model.control_limits
            if val < l_min or val > l_max:
                return self._alert(var, "LIMIT_FAIL", f"[{l_min:.2f},{l_max:.2f}]", val, "WARNING")

            if model.ar_model_params is not None:
                if model.last_seen_time == 0:
                    delta_steps = 1
                else:
                    delta_sec = var.timestamp - model.last_seen_time
                    delta_steps = max(1, int(round(delta_sec / self.sampling_rate)))

                params = model.ar_model_params
                mu = model.ar_mean

                for _ in range(delta_steps):
                    if len(model.history_buffer) >= model.ar_lag_p:
                        pred_centered = 0.0
                        for i in range(model.ar_lag_p):
                            past_val = model.history_buffer[-(i + 1)]
                            pred_centered += params[i] * (past_val - mu)

                        pred = mu + pred_centered
                        residual = val - pred
                        model.prediction_errors.append(residual)

                        if len(model.prediction_errors) >= 10:
                            test_var = np.var(model.prediction_errors)
                            train_var = model.train_residual_variance if model.train_residual_variance > 0 else 1e-6
                            f_stat = test_var / train_var

                            crit = f.ppf(1 - self.alpha, len(model.prediction_errors) - 1, 1000)

                            if f_stat > crit:
                                return self._alert(var, "AR_ANOMALY", f"Pred:{pred:.2f}", val, "CRITICAL")

                    model.history_buffer.append(val)

                model.last_seen_time = var.timestamp
                model.last_seen_value = val

        return None

    def _alert(self, var, atype, exp, obs, sev):
        alert = DetectionAlert(var.timestamp, var.frame_num, var.tag_id, atype, sev, exp, obs, "Anomaly")
        self.alerts.append(alert)
        return alert


# -------------------------------------------------------------------------
# Main Monitor Execution
# -------------------------------------------------------------------------

class IndustrialS7Monitor:
    def __init__(self, interface="lo"):
        self.interface = interface
        self.extractor = S7DataExtractor()
        self.characteriser = DataCharacterisation()
        self.detector = MultiModelDetector()
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

        # Sort by Tag ID for readability
        sorted_models = sorted(self.detector.models.items())

        for tag, model in sorted_models:
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
    monitor = IndustrialS7Monitor(interface="以太网")

    MODEL_FILE = "s7_model.pkl"
    PCAP_FILE = "../dataset/s7comm_train.pcap"

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