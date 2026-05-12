"""
Extractor de features de flujos de red compatibles con CICIDS2017.

Captura paquetes con Scapy, agrupa en flujos bidireccionales (5-tuple)
y extrae las 47 features auditadas que espera el modelo v2 (RF + XGBoost).

El orden de FEATURE_NAMES debe coincidir EXACTAMENTE con
models/feature_names_v2.joblib del ML API — si no, la API rechaza con
"Expected 47 features, got N".
"""
import time
import numpy as np
from collections import defaultdict

# Las 47 features auditadas del modelo v2 (orden exacto).
# Generado a partir de models/feature_names_v2.joblib.
# Auditoría: 30 cols dropeadas (8 constantes + 6 leakage + 7 redundancia
# matemática + 9 VIF iterativo). Detalles en notebooks/02 y /03.
FEATURE_NAMES = [
    'Flow_Duration', 'Total_Fwd_Packets', 'Total_Backward_Packets',
    'Total_Length_of_Fwd_Packets', 'Total_Length_of_Bwd_Packets',
    'Fwd_Packet_Length_Max', 'Fwd_Packet_Length_Min', 'Fwd_Packet_Length_Mean',
    'Bwd_Packet_Length_Max', 'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean',
    'Bwd_Packet_Length_Std',
    'Flow_Bytes_per_s', 'Flow_Packets_per_s',
    'Flow_IAT_Mean', 'Flow_IAT_Std', 'Flow_IAT_Max', 'Flow_IAT_Min',
    'Fwd_IAT_Mean', 'Fwd_IAT_Std', 'Fwd_IAT_Min',
    'Bwd_IAT_Total', 'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min',
    'Fwd_PSH_Flags', 'Fwd_URG_Flags',
    'Bwd_Packets_per_s',
    'Min_Packet_Length', 'Max_Packet_Length', 'Packet_Length_Mean',
    'Packet_Length_Std', 'Packet_Length_Variance',
    'FIN_Flag_Count', 'RST_Flag_Count', 'PSH_Flag_Count', 'ACK_Flag_Count',
    'URG_Flag_Count',
    'Down_per_Up_Ratio',
    'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active_Mean', 'Active_Std', 'Active_Max', 'Active_Min',
    'Idle_Std',
]

N_FEATURES = 47


class FlowAggregator:
    """Agrupa paquetes en flujos bidireccionales por 5-tuple."""

    def __init__(self, timeout=120):
        self.flows = defaultdict(lambda: {
            'fwd_packets': [], 'bwd_packets': [],
            'fwd_sizes': [], 'bwd_sizes': [],
            'fwd_times': [], 'bwd_times': [],
            'fwd_headers': [], 'bwd_headers': [],
            'flags': defaultdict(int),
            'start_time': None, 'last_time': None,
            'protocol': 6,  # TCP default
            'src_ip': '', 'dst_ip': '',
            'src_port': 0, 'dst_port': 0,
            'init_fwd_win': 0, 'init_bwd_win': 0,
            'fwd_psh': 0, 'fwd_urg': 0,
        })
        self.timeout = timeout

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port, proto):
        """Genera clave bidireccional."""
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port, proto)
        return (dst_ip, dst_port, src_ip, src_port, proto)

    def add_packet(self, src_ip, dst_ip, src_port, dst_port, proto,
                   pkt_size, header_size, timestamp, flags=None, window=0):
        """Agrega un paquete al flujo correspondiente."""
        key = self._flow_key(src_ip, dst_ip, src_port, dst_port, proto)
        flow = self.flows[key]

        if flow['start_time'] is None:
            flow['start_time'] = timestamp
            flow['src_ip'] = src_ip
            flow['dst_ip'] = dst_ip
            flow['src_port'] = src_port
            flow['dst_port'] = dst_port
            flow['protocol'] = proto

        flow['last_time'] = timestamp

        # Determinar direccion (forward = mismo src que el primer paquete)
        is_fwd = (src_ip == flow['src_ip'] and src_port == flow['src_port'])

        if is_fwd:
            flow['fwd_sizes'].append(pkt_size)
            flow['fwd_times'].append(timestamp)
            flow['fwd_headers'].append(header_size)
            if not flow['fwd_sizes'] or len(flow['fwd_sizes']) == 1:
                flow['init_fwd_win'] = window
            if flags:
                if flags.get('PSH'): flow['fwd_psh'] += 1
                if flags.get('URG'): flow['fwd_urg'] += 1
        else:
            flow['bwd_sizes'].append(pkt_size)
            flow['bwd_times'].append(timestamp)
            flow['bwd_headers'].append(header_size)
            if not flow['bwd_sizes'] or len(flow['bwd_sizes']) == 1:
                flow['init_bwd_win'] = window

        # Flags globales
        if flags:
            for f in ['FIN', 'RST', 'PSH', 'ACK', 'URG', 'ECE']:
                if flags.get(f):
                    flow['flags'][f] += 1

    def extract_features(self):
        """Extrae features de todos los flujos activos. Retorna lista de dicts."""
        results = []
        for key, flow in self.flows.items():
            if flow['start_time'] is None:
                continue
            features = self._compute_flow_features(flow)
            results.append({
                'features': features,
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'src_port': flow['src_port'],
                'dst_port': flow['dst_port'],
                'protocol': flow['protocol'],
                'n_packets': len(flow['fwd_sizes']) + len(flow['bwd_sizes']),
            })
        return results

    def _compute_flow_features(self, flow):
        """Calcula las 47 features auditadas (v2) de un flujo, en el orden
        exacto de FEATURE_NAMES."""
        fwd_s = flow['fwd_sizes'] or [0]
        bwd_s = flow['bwd_sizes'] or [0]
        fwd_t = flow['fwd_times'] or [0]
        bwd_t = flow['bwd_times'] or [0]
        all_s = fwd_s + bwd_s

        duration = (flow['last_time'] - flow['start_time']) * 1e6 if flow['start_time'] else 0
        duration = max(duration, 1)  # evitar division por cero (microseg)
        duration_s = duration / 1e6

        n_fwd = len(fwd_s)
        n_bwd = len(bwd_s)
        n_total = n_fwd + n_bwd

        # IAT (inter-arrival time) en microsegundos
        def iat(times):
            if len(times) < 2: return [0]
            return [abs(times[i] - times[i-1]) * 1e6 for i in range(1, len(times))]

        flow_iat = iat(sorted(fwd_t + bwd_t))
        fwd_iat = iat(fwd_t)
        bwd_iat = iat(bwd_t)

        def safe_stat(arr, func, default=0):
            if not arr: return default
            try: return float(func(arr))
            except: return default

        # 47 features en el ORDEN EXACTO de FEATURE_NAMES (= feature_names_v2.joblib)
        features = [
            # 1-3: Flow basics
            duration, n_fwd, n_bwd,
            # 4-5: Length totals
            sum(fwd_s), sum(bwd_s),
            # 6-8: Fwd packet length
            max(fwd_s), min(fwd_s), safe_stat(fwd_s, np.mean),
            # 9-12: Bwd packet length (con Std nuevo en v2)
            max(bwd_s), min(bwd_s), safe_stat(bwd_s, np.mean), safe_stat(bwd_s, np.std),
            # 13-14: Flow rates
            sum(all_s) / duration_s if duration_s > 0 else 0,
            n_total / duration_s if duration_s > 0 else 0,
            # 15-18: Flow IAT
            safe_stat(flow_iat, np.mean), safe_stat(flow_iat, np.std),
            max(flow_iat) if flow_iat else 0, min(flow_iat) if flow_iat else 0,
            # 19-21: Fwd IAT (sin Total ni Max en v2)
            safe_stat(fwd_iat, np.mean), safe_stat(fwd_iat, np.std),
            min(fwd_iat) if fwd_iat else 0,
            # 22-26: Bwd IAT (Total y Max sí están en v2)
            sum(bwd_iat), safe_stat(bwd_iat, np.mean), safe_stat(bwd_iat, np.std),
            max(bwd_iat) if bwd_iat else 0, min(bwd_iat) if bwd_iat else 0,
            # 27-28: Fwd flags
            flow['fwd_psh'], flow['fwd_urg'],
            # 29: Bwd packets/s (Fwd Packets/s NO está en v2 por colinealidad)
            n_bwd / duration_s if duration_s > 0 else 0,
            # 30-34: Packet length stats
            min(all_s), max(all_s),
            safe_stat(all_s, np.mean), safe_stat(all_s, np.std), safe_stat(all_s, np.var),
            # 35-39: Flag counts (sin ECE en v2)
            flow['flags']['FIN'], flow['flags']['RST'],
            flow['flags']['PSH'], flow['flags']['ACK'], flow['flags']['URG'],
            # 40: Down/Up Ratio
            n_bwd / n_fwd if n_fwd > 0 else 0,
            # 41-42: act_data_pkt_fwd, min_seg_size_forward
            sum(1 for s in fwd_s if s > 0),
            min(fwd_s) if fwd_s else 0,
            # 43-46: Active time (simplificado: medio flujo activo, medio idle)
            duration / 2, 0, duration / 2, 0,
            # 47: Idle Std (Idle Mean/Max/Min se dropearon en audit por colinealidad)
            0,
        ]

        # Asegurar longitud + sanear NaN/inf
        features = features[:N_FEATURES]
        while len(features) < N_FEATURES:
            features.append(0)
        features = [0 if (np.isnan(v) or np.isinf(v)) else float(v) for v in features]
        return features

    def clear(self):
        """Limpia todos los flujos."""
        self.flows.clear()
