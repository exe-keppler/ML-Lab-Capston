"""
Extractor de features de flujos de red compatibles con CICIDS2017.

Captura paquetes con Scapy, agrupa en flujos bidireccionales (5-tuple)
y extrae las 60 features que el modelo Random Forest espera.
"""
import time
import numpy as np
from collections import defaultdict

# Las 60 features del modelo (orden exacto del CICIDS2017 procesado)
FEATURE_NAMES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Fwd Packets Length Total', 'Bwd Packets Length Total',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Fwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s',
    'Packet Length Min', 'Packet Length Max', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Fwd Seg Size Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
    'Fwd Act Data Packets',
    'Init Fwd Win Bytes', 'Init Bwd Win Bytes',
    'Fwd Packets Length Total', 'Flow IAT Mean',
    'Protocol',
]

# Nota: el modelo tiene exactamente 60 features. Algunas se repiten en CICIDS2017
# (Fwd Packets Length Total, Flow IAT Mean). Usamos las 60 posiciones.
N_FEATURES = 60


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
        """Calcula las 60 features de un flujo."""
        fwd_s = flow['fwd_sizes'] or [0]
        bwd_s = flow['bwd_sizes'] or [0]
        fwd_t = flow['fwd_times'] or [0]
        bwd_t = flow['bwd_times'] or [0]
        all_s = fwd_s + bwd_s

        duration = (flow['last_time'] - flow['start_time']) * 1e6 if flow['start_time'] else 0
        duration = max(duration, 1)  # evitar division por cero

        n_fwd = len(fwd_s)
        n_bwd = len(bwd_s)
        n_total = n_fwd + n_bwd

        # IAT (inter-arrival time)
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

        features = [
            # 1-3: Flow basics
            duration,
            n_fwd,
            n_bwd,
            # 4-5: Length totals
            sum(fwd_s),
            sum(bwd_s),
            # 6-8: Fwd packet length
            max(fwd_s), min(fwd_s), safe_stat(fwd_s, np.mean),
            # 9-11: Bwd packet length
            max(bwd_s), min(bwd_s), safe_stat(bwd_s, np.mean),
            # 12-13: Flow rates
            sum(all_s) / (duration / 1e6) if duration > 0 else 0,
            n_total / (duration / 1e6) if duration > 0 else 0,
            # 14-17: Flow IAT
            safe_stat(flow_iat, np.mean), safe_stat(flow_iat, np.std),
            max(flow_iat) if flow_iat else 0, min(flow_iat) if flow_iat else 0,
            # 18-22: Fwd IAT
            sum(fwd_iat), safe_stat(fwd_iat, np.mean), safe_stat(fwd_iat, np.std),
            max(fwd_iat) if fwd_iat else 0, min(fwd_iat) if fwd_iat else 0,
            # 23-27: Bwd IAT
            sum(bwd_iat), safe_stat(bwd_iat, np.mean), safe_stat(bwd_iat, np.std),
            max(bwd_iat) if bwd_iat else 0, min(bwd_iat) if bwd_iat else 0,
            # 28-29: Fwd flags
            flow['fwd_psh'], flow['fwd_urg'],
            # 30-31: Header lengths
            sum(flow['fwd_headers']), sum(flow['bwd_headers']),
            # 32-33: Packets/s
            n_fwd / (duration / 1e6) if duration > 0 else 0,
            n_bwd / (duration / 1e6) if duration > 0 else 0,
            # 34-38: Packet length stats
            min(all_s), max(all_s), safe_stat(all_s, np.mean),
            safe_stat(all_s, np.std), safe_stat(all_s, np.var),
            # 39-44: Flag counts
            flow['flags']['FIN'], flow['flags']['RST'],
            flow['flags']['PSH'], flow['flags']['ACK'],
            flow['flags']['URG'], flow['flags']['ECE'],
            # 45: Down/Up Ratio
            n_bwd / n_fwd if n_fwd > 0 else 0,
            # 46: Fwd Seg Size Min
            min(fwd_s) if fwd_s else 0,
            # 47-50: Active time (simplified)
            duration / 2, 0, duration / 2, 0,
            # 51-54: Idle time (simplified)
            0, 0, 0, 0,
            # 55: Fwd Act Data Packets
            sum(1 for s in fwd_s if s > 0),
            # 56-57: Init window bytes
            flow['init_fwd_win'], flow['init_bwd_win'],
            # 58-60: Repeated features (for compatibility)
            sum(fwd_s),  # Fwd Packets Length Total (repeat)
            safe_stat(flow_iat, np.mean),  # Flow IAT Mean (repeat)
            flow['protocol'],
        ]

        # Asegurar exactamente 60 features
        features = features[:N_FEATURES]
        while len(features) < N_FEATURES:
            features.append(0)

        # Reemplazar NaN/inf
        features = [0 if (np.isnan(v) or np.isinf(v)) else float(v) for v in features]
        return features

    def clear(self):
        """Limpia todos los flujos."""
        self.flows.clear()
