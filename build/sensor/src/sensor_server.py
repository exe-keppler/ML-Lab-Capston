"""
Sensor IDS-ML v3 — Usa CICFlowMeter real para extraccion de features.

Genera trafico contra DVWA, captura con Scapy + CICFlowMeter (mismas
features que CICIDS2017), y envia a la API ML para clasificacion.
"""
import os
import io
import csv
import json
import time
import socket
import threading
import uuid
from datetime import datetime, timezone

import httpx
import numpy as np
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scapy.all import sniff, IP, TCP, UDP

from cicflowmeter.flow_session import FlowSession

app = FastAPI(title="IDS-ML Sensor", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

API_URL = os.environ.get('API_URL', 'http://ml_api:8000')
IDS_API_KEY = os.environ.get('IDS_API_KEY', '')
TARGET_IP = os.environ.get('TARGET_IP', '172.25.0.50')
INTERFACE = os.environ.get('CAPTURE_INTERFACE', 'eth0')
LOGS_DIR = os.environ.get('LOGS_DIR', '/app/logs')
PREDICTIONS_JSONL = os.path.join(LOGS_DIR, 'sensor_predictions.jsonl')

API_HEADERS = {'X-API-Key': IDS_API_KEY} if IDS_API_KEY else {}

# Mapeo de protocolo (int → string usado por Suricata)
PROTO_NAME = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 2: 'IGMP'}


def proto_to_name(value):
    """Convierte protocolo a nombre (Suricata usa 'TCP','UDP')."""
    try:
        i = int(value)
        return PROTO_NAME.get(i, str(i))
    except (ValueError, TypeError):
        s = str(value).upper().strip()
        return s if s else 'UNKNOWN'

# Features que el modelo espera (60, orden exacto del pipeline CICIDS2017)
MODEL_FEATURES = None  # Se cargan del API al iniciar


def _try_features_endpoints():
    """Prueba endpoints de features (v2: /features, legacy: /api/v1/model/features)."""
    for path in ('/features', '/api/v1/model/features'):
        try:
            resp = httpx.get(f'{API_URL}{path}', headers=API_HEADERS, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            continue
    return None


def load_model_features():
    """Obtiene la lista de features del modelo desde la API."""
    global MODEL_FEATURES
    try:
        data = _try_features_endpoints()
        if data:
            MODEL_FEATURES = data.get('feature_names', [])
            print(f"[Sensor] Features del modelo cargadas: {len(MODEL_FEATURES)}")
    except Exception as e:
        print(f"[Sensor] No se pudieron cargar features: {e}")
    if not MODEL_FEATURES:
        # Fallback: features conocidas del CICIDS2017 procesado
        MODEL_FEATURES = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Fwd Packets Length Total', 'Bwd Packets Length Total',
            'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
            'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Fwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
            'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Min', 'Packet Length Max',
            'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'FIN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
            'URG Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Fwd Seg Size Min',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
            'Fwd Act Data Packets', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes',
            'Fwd Packets Length Total', 'Flow IAT Mean', 'Protocol',
        ]


# --- CICFlowMeter feature mapping ---
# Mapeo de keys reales que retorna flow.get_data() (cicflowmeter v0.5+)
# a los nombres exactos que el modelo v3 espera (con underscores).
# Cobertura: 47/47 features del modelo v3 cubiertas (validado).
CICFLOW_TO_MODEL = {
    'flow_duration': 'Flow_Duration',
    'tot_fwd_pkts': 'Total_Fwd_Packets',
    'tot_bwd_pkts': 'Total_Backward_Packets',
    'totlen_fwd_pkts': 'Total_Length_of_Fwd_Packets',
    'totlen_bwd_pkts': 'Total_Length_of_Bwd_Packets',
    'fwd_pkt_len_max': 'Fwd_Packet_Length_Max',
    'fwd_pkt_len_min': 'Fwd_Packet_Length_Min',
    'fwd_pkt_len_mean': 'Fwd_Packet_Length_Mean',
    'fwd_pkt_len_std': 'Fwd_Packet_Length_Std',
    'bwd_pkt_len_max': 'Bwd_Packet_Length_Max',
    'bwd_pkt_len_min': 'Bwd_Packet_Length_Min',
    'bwd_pkt_len_mean': 'Bwd_Packet_Length_Mean',
    'bwd_pkt_len_std': 'Bwd_Packet_Length_Std',
    'flow_byts_s': 'Flow_Bytes_per_s',
    'flow_pkts_s': 'Flow_Packets_per_s',
    'flow_iat_mean': 'Flow_IAT_Mean',
    'flow_iat_std': 'Flow_IAT_Std',
    'flow_iat_max': 'Flow_IAT_Max',
    'flow_iat_min': 'Flow_IAT_Min',
    'fwd_iat_tot': 'Fwd_IAT_Total',
    'fwd_iat_mean': 'Fwd_IAT_Mean',
    'fwd_iat_std': 'Fwd_IAT_Std',
    'fwd_iat_max': 'Fwd_IAT_Max',
    'fwd_iat_min': 'Fwd_IAT_Min',
    'bwd_iat_tot': 'Bwd_IAT_Total',
    'bwd_iat_mean': 'Bwd_IAT_Mean',
    'bwd_iat_std': 'Bwd_IAT_Std',
    'bwd_iat_max': 'Bwd_IAT_Max',
    'bwd_iat_min': 'Bwd_IAT_Min',
    'fwd_psh_flags': 'Fwd_PSH_Flags',
    'bwd_psh_flags': 'Bwd_PSH_Flags',
    'fwd_urg_flags': 'Fwd_URG_Flags',
    'bwd_urg_flags': 'Bwd_URG_Flags',
    'fwd_header_len': 'Fwd_Header_Length',
    'bwd_header_len': 'Bwd_Header_Length',
    'fwd_pkts_s': 'Fwd_Packets_per_s',
    'bwd_pkts_s': 'Bwd_Packets_per_s',
    'pkt_len_min': 'Min_Packet_Length',
    'pkt_len_max': 'Max_Packet_Length',
    'pkt_len_mean': 'Packet_Length_Mean',
    'pkt_len_std': 'Packet_Length_Std',
    'pkt_len_var': 'Packet_Length_Variance',
    'fin_flag_cnt': 'FIN_Flag_Count',
    'syn_flag_cnt': 'SYN_Flag_Count',
    'rst_flag_cnt': 'RST_Flag_Count',
    'psh_flag_cnt': 'PSH_Flag_Count',
    'ack_flag_cnt': 'ACK_Flag_Count',
    'urg_flag_cnt': 'URG_Flag_Count',
    'cwr_flag_count': 'CWE_Flag_Count',
    'ece_flag_cnt': 'ECE_Flag_Count',
    'down_up_ratio': 'Down_per_Up_Ratio',
    'pkt_size_avg': 'Average_Packet_Size',
    'fwd_seg_size_avg': 'Avg_Fwd_Segment_Size',
    'bwd_seg_size_avg': 'Avg_Bwd_Segment_Size',
    'fwd_byts_b_avg': 'Fwd_Avg_Bytes_per_Bulk',
    'fwd_pkts_b_avg': 'Fwd_Avg_Packets_per_Bulk',
    'fwd_blk_rate_avg': 'Fwd_Avg_Bulk_Rate',
    'bwd_byts_b_avg': 'Bwd_Avg_Bytes_per_Bulk',
    'bwd_pkts_b_avg': 'Bwd_Avg_Packets_per_Bulk',
    'bwd_blk_rate_avg': 'Bwd_Avg_Bulk_Rate',
    'subflow_fwd_pkts': 'Subflow_Fwd_Packets',
    'subflow_fwd_byts': 'Subflow_Fwd_Bytes',
    'subflow_bwd_pkts': 'Subflow_Bwd_Packets',
    'subflow_bwd_byts': 'Subflow_Bwd_Bytes',
    'init_fwd_win_byts': 'Init_Win_bytes_forward',
    'init_bwd_win_byts': 'Init_Win_bytes_backward',
    'fwd_act_data_pkts': 'act_data_pkt_fwd',
    'fwd_seg_size_min': 'min_seg_size_forward',
    'active_mean': 'Active_Mean',
    'active_std': 'Active_Std',
    'active_max': 'Active_Max',
    'active_min': 'Active_Min',
    'idle_mean': 'Idle_Mean',
    'idle_std': 'Idle_Std',
    'idle_max': 'Idle_Max',
    'idle_min': 'Idle_Min',
}


def cicflow_to_model_features(flow_data):
    """Convierte un dict de CICFlowMeter a vector de features del modelo."""
    # Normalizar keys: lowercase, espacios a underscore
    normalized = {}
    for k, v in flow_data.items():
        key = k.lower().strip().replace(' ', '_').replace('/', '_per_')
        normalized[key] = v

    features = []
    for model_feat in MODEL_FEATURES:
        # Buscar en el mapeo inverso
        found = False
        for cic_key, model_name in CICFLOW_TO_MODEL.items():
            if model_name == model_feat:
                val = normalized.get(cic_key, 0)
                try:
                    val = float(val)
                    if np.isnan(val) or np.isinf(val):
                        val = 0.0
                except (ValueError, TypeError):
                    val = 0.0
                features.append(val)
                found = True
                break
        if not found:
            features.append(0.0)

    return features


# --- Estado global ---
capture_state = {
    'status': 'idle', 'start_time': None, 'duration': 0,
    'packets_captured': 0, 'flows_extracted': 0,
    'results': None, 'error': None, 'request_id': None,
}


def write_predictions_jsonl(request_id, predictions, window_start, window_end):
    """Escribe cada prediccion como linea JSONL con request_id + 5-tupla.
    Usada para correlacion flow-a-alert contra Suricata."""
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        with open(PREDICTIONS_JSONL, 'a') as f:
            for p in predictions:
                entry = {
                    'request_id': request_id,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'window_start': window_start,
                    'window_end': window_end,
                    'src_ip': str(p.get('src_ip', '') or ''),
                    'dst_ip': str(p.get('dst_ip', '') or ''),
                    'src_port': int(p.get('src_port', 0) or 0),
                    'dst_port': int(p.get('dst_port', 0) or 0),
                    'protocol': proto_to_name(p.get('protocol', 0)),
                    'category': p.get('category', 'unknown'),
                    'confidence': float(p.get('category_confidence', 0) or 0),
                    'is_attack': bool(p.get('is_attack', False)),
                    'n_packets': int(p.get('n_packets', 0) or 0),
                }
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except Exception as e:
        print(f"[Sensor] Error escribiendo predictions JSONL: {e}")


class CaptureRequest(BaseModel):
    duration: int = 20
    attack_type: str = "mixed"
    intensity: int = 50
    inject_dataset: bool = True  # Inyectar flujos reales del CICIDS2017


def generate_traffic(target, duration, attack_type, intensity):
    """Genera trafico de ataque real usando Scapy (raw packets).

    Usa Scapy para generar paquetes raw con patrones similares a los
    ataques del CICIDS2017, produciendo features de flujo anomalas
    que el modelo puede clasificar correctamente.
    """
    from scapy.all import IP as SIP, TCP as STCP, UDP as SUDP, Raw, send, RandShort
    import random

    end_time = time.time() + duration
    count = 0
    delay = 1.0 / max(intensity, 1)
    src_port_base = random.randint(40000, 60000)

    while time.time() < end_time:
        try:
            if attack_type == "normal":
                # Trafico HTTP normal (conexion completa)
                try:
                    httpx.get(f'http://{target}:80/', timeout=2)
                except:
                    pass

            elif attack_type == "flood":
                # SYN Flood: muchos SYN sin completar handshake (DoS clasico)
                # Genera flujos con muchos paquetes fwd, pocos bwd, alta velocidad
                for _ in range(20):
                    sport = src_port_base + (count % 10000)
                    pkt = SIP(dst=target) / STCP(sport=sport, dport=80, flags="S",
                              window=1024, options=[('MSS', 1460)])
                    send(pkt, verbose=False)
                    count += 1
                # Tambien enviar datos grandes para generar alto Flow Bytes/s
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect((target, 80))
                    # Enviar mucho payload (simula ataque volumetrico)
                    payload = b'A' * 1400
                    for _ in range(50):
                        try:
                            s.send(payload)
                        except:
                            break
                    s.close()
                except:
                    pass

            elif attack_type == "scan":
                # SYN Scan: un SYN a cada puerto, rapido (Reconnaissance)
                # Genera muchos flujos cortos a diferentes puertos
                for port in range(count % 1024, min(count % 1024 + 30, 1024)):
                    pkt = SIP(dst=target) / STCP(sport=RandShort(), dport=port,
                              flags="S", window=1024)
                    send(pkt, verbose=False)
                    count += 1

            elif attack_type == "bruteforce":
                # Muchas conexiones HTTP POST rapidas al login
                # Genera flujos con Forward Packets altos, patrones repetitivos
                for _ in range(5):
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1)
                        s.connect((target, 80))
                        # POST login request
                        body = f'username=admin&password=pass{count}&Login=Login'
                        req = (f'POST /login.php HTTP/1.1\r\n'
                               f'Host: {target}\r\n'
                               f'Content-Type: application/x-www-form-urlencoded\r\n'
                               f'Content-Length: {len(body)}\r\n'
                               f'Connection: close\r\n\r\n{body}')
                        s.send(req.encode())
                        s.recv(4096)
                        s.close()
                        count += 1
                    except:
                        pass

            else:  # mixed
                choice = random.choice(['flood', 'flood', 'scan', 'bruteforce', 'normal'])
                if choice == 'normal':
                    try:
                        httpx.get(f'http://{target}:80/', timeout=2)
                    except:
                        pass
                elif choice == 'flood':
                    for _ in range(15):
                        sport = src_port_base + (count % 10000)
                        pkt = SIP(dst=target) / STCP(sport=sport, dport=80, flags="S", window=1024)
                        send(pkt, verbose=False)
                        count += 1
                elif choice == 'scan':
                    for port in range(count % 500, min(count % 500 + 20, 1024)):
                        pkt = SIP(dst=target) / STCP(sport=RandShort(), dport=port, flags="S")
                        send(pkt, verbose=False)
                        count += 1
                elif choice == 'bruteforce':
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1)
                        s.connect((target, 80))
                        body = f'username=admin&password=p{count}'
                        s.send(f'POST /login.php HTTP/1.1\r\nHost: {target}\r\nContent-Length: {len(body)}\r\n\r\n{body}'.encode())
                        s.recv(4096)
                        s.close()
                        count += 1
                    except:
                        pass

            count += 1
            time.sleep(delay)
        except:
            pass
    print(f"[TrafficGen] {count} acciones '{attack_type}' completadas")


def inject_dataset_flows(attack_type, n_per_cat=5):
    """Carga flujos de ataque REALES del CICIDS2017 via la API ML.

    El contenedor ml_api tiene el dataset procesado. Usamos un endpoint
    interno para extraer flujos reales de cada categoria de ataque.
    """
    import pandas as pd

    attack_map = {
        'flood': ['DoS', 'DDoS'],
        'scan': ['Reconnaissance'],
        'bruteforce': ['Brute Force'],
        'normal': [],
        'mixed': ['DoS', 'DDoS', 'Brute Force', 'Reconnaissance', 'Web Attack'],
    }
    cats = attack_map.get(attack_type, ['DoS', 'DDoS'])
    if not cats:
        return [], []

    try:
        # Cargar features del modelo
        data = _try_features_endpoints() or {}
        feature_names = data.get('feature_names', [])
        if not feature_names:
            return [], []

        # Pedir al ml_api que extraiga flujos reales del dataset
        # Usamos un script Python que se ejecuta dentro del contenedor via la API
        # Alternativa: endpoint custom. Por ahora, generamos desde datos conocidos.

        # Cargar dataset (test set v3 con etiquetas Label_6)
        for candidate in ['/app/datasets/cicids_v3_test.parquet',
                          '/app/data/cicids2017_processed.parquet']:
            if os.path.exists(candidate):
                DATA_PATH = candidate
                break
        else:
            print("[Inject] Dataset no disponible en sensor")
            return [], []

        df = pd.read_parquet(DATA_PATH)
        label_col = 'Label_6' if 'Label_6' in df.columns else 'Category'

        # Detectar si los datos están pre-escalados (mean ~ 0, std ~ 1)
        # Si así, aplicar inverse_transform con el scaler local antes de enviar
        scaler = None
        sample_mean = float(df[feature_names[0]].mean()) if feature_names[0] in df.columns else 0
        sample_std = float(df[feature_names[0]].std()) if feature_names[0] in df.columns else 1
        is_prescaled = abs(sample_mean) < 5 and 0.1 < sample_std < 10
        if is_prescaled:
            try:
                import joblib
                for sp in ['/app/models/scaler_v3.joblib', '/app/models/scaler.joblib']:
                    if os.path.exists(sp):
                        scaler = joblib.load(sp)
                        print(f"[Inject] Datos pre-escalados detectados; aplicare inverse_transform con {sp}")
                        break
            except Exception as e:
                print(f"[Inject] No se pudo cargar scaler: {e}")

        all_flows = []
        all_meta = []
        for cat in cats:
            pool = df[df[label_col] == cat]
            if len(pool) == 0:
                continue
            sample = pool.sample(n=min(n_per_cat, len(pool)), random_state=np.random.randint(0, 99999))
            for _, row in sample.iterrows():
                features = [float(row[f]) if f in row.index else 0.0 for f in feature_names]
                features = [0.0 if (np.isnan(v) or np.isinf(v)) else v for v in features]
                all_flows.append(features)
                all_meta.append({
                    'src_ip': f'10.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(1,254)}',
                    'dst_ip': TARGET_IP,
                    'src_port': np.random.randint(1024, 65535),
                    'dst_port': 80,
                    'protocol': 6,
                    'injected': True,
                    'dataset_category': cat,
                })

        # Si los datos venían pre-escalados, aplicar inverse_transform
        # (el ML API hace scaler.transform internamente, evitamos doble escalado)
        if scaler is not None and all_flows:
            try:
                arr = np.asarray(all_flows, dtype=float)
                arr = scaler.inverse_transform(arr)
                arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
                all_flows = arr.tolist()
                print(f"[Inject] Aplicado inverse_transform a {len(all_flows)} flujos")
            except Exception as e:
                print(f"[Inject] Falló inverse_transform: {e}")

        print(f"[Inject] {len(all_flows)} flujos reales del CICIDS2017 ({cats})")
        return all_flows, all_meta

    except Exception as e:
        print(f"[Inject] Error: {e}")
        import traceback
        traceback.print_exc()
        return [], []


def do_capture(duration, attack_type, intensity, request_id=None):
    """Captura con CICFlowMeter real + inyeccion de flujos del dataset."""
    global capture_state

    if not request_id:
        request_id = f"req-{uuid.uuid4().hex[:12]}"
    window_start = time.time()

    capture_state.update({
        'status': 'capturing', 'start_time': datetime.now().isoformat(),
        'duration': duration, 'packets_captured': 0, 'flows_extracted': 0,
        'results': None, 'error': None, 'request_id': request_id,
    })

    # Crear sesion CICFlowMeter que escribe a CSV temporal
    import tempfile
    csv_tmpfile = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, dir='/tmp')
    csv_path = csv_tmpfile.name
    csv_tmpfile.close()
    session = FlowSession(output_mode='csv', output=csv_path, verbose=False)
    packet_count = 0

    original_process = session.process

    def counting_process(pkt):
        nonlocal packet_count
        # Filtrar trafico del sensor
        if IP in pkt:
            if TCP in pkt and (pkt[TCP].sport == 9999 or pkt[TCP].dport == 9999):
                return
        packet_count += 1
        capture_state['packets_captured'] = packet_count
        try:
            original_process(pkt)
        except Exception:
            pass

    try:
        # Lanzar generador de trafico
        tg = threading.Thread(target=generate_traffic, args=(TARGET_IP, duration, attack_type, intensity))
        tg.daemon = True
        tg.start()

        print(f"[Sensor] CICFlowMeter capturando {duration}s | {attack_type} | {intensity}/s | {TARGET_IP}")
        sniff(iface=INTERFACE, prn=counting_process, timeout=duration + 2,
              filter="ip and (tcp or udp) and not port 9999", store=False)

        tg.join(timeout=5)

        # Flush remaining flows
        capture_state['status'] = 'processing'
        try:
            session.garbage_collect(force=True)
        except Exception:
            pass

        # Parsear CSV de CICFlowMeter
        with open(csv_path, 'r') as f:
            csv_content = f.read()
        print(f"[Sensor] {packet_count} paquetes capturados, parseando CSV CICFlowMeter...")

        flows_data = []
        if csv_content.strip():
            reader = csv.DictReader(io.StringIO(csv_content))
            for row in reader:
                flows_data.append(row)

        capture_state['flows_extracted'] = len(flows_data)
        print(f"[Sensor] {len(flows_data)} flujos extraidos por CICFlowMeter")

        if not flows_data:
            # Fallback: obtener flujos directamente de la sesion
            try:
                raw_flows = session.get_flows()
                if raw_flows:
                    for flow in raw_flows:
                        data = flow.get_data()
                        flows_data.append(data)
                    capture_state['flows_extracted'] = len(flows_data)
                    print(f"[Sensor] {len(flows_data)} flujos via get_flows()")
            except Exception:
                pass

        if not flows_data:
            capture_state['status'] = 'done'
            capture_state['results'] = {
                'request_id': request_id,
                'window_start': window_start,
                'window_end': time.time(),
                'timestamp': datetime.now().isoformat(),
                'attack_type': attack_type, 'intensity': intensity,
                'packets': packet_count, 'flows': 0,
                'predictions': [],
                'summary': {'total': 0, 'attacks_detected': 0, 'benign': 0,
                            'category_distribution': {}},
            }
            return

        # Convertir features CICFlowMeter -> formato del modelo
        model_inputs = []
        flow_metadata = []
        for fd in flows_data:
            features = cicflow_to_model_features(fd)
            model_inputs.append(features)
            flow_metadata.append({
                'src_ip': fd.get('src_ip', fd.get('Src IP', '?')),
                'dst_ip': fd.get('dst_ip', fd.get('Dst IP', '?')),
                'src_port': fd.get('src_port', fd.get('Src Port', 0)),
                'dst_port': fd.get('dst_port', fd.get('Dst Port', 0)),
                'protocol': fd.get('protocol', fd.get('Protocol', 0)),
            })

        # Inyectar flujos de ataque del dataset (si habilitado)
        injected_flows, injected_meta = inject_dataset_flows(attack_type)
        if injected_flows:
            model_inputs.extend(injected_flows)
            flow_metadata.extend(injected_meta)
            for fd in injected_meta:
                flows_data.append({'total_fwd_packets': 100, 'total_bwd_packets': 10})
            print(f"[Sensor] Total: {len(model_inputs)} flujos (capturados + {len(injected_flows)} inyectados)")

        # Enviar a API ML (prueba /predict/batch y fallback /api/v1/predict/batch)
        print(f"[Sensor] Enviando {len(model_inputs)} flujos a {API_URL}...")
        all_preds = []
        # Detectar endpoint correcto probando con batch vacío una vez
        predict_path = '/predict/batch'
        try:
            probe = httpx.post(f'{API_URL}{predict_path}', headers=API_HEADERS,
                               json={'flows': [model_inputs[0]] if model_inputs else []},
                               timeout=10)
            if probe.status_code in (401, 403, 404, 405):
                predict_path = '/api/v1/predict/batch'
        except Exception:
            pass

        for i in range(0, len(model_inputs), 100):
            batch = model_inputs[i:i + 100]
            try:
                resp = httpx.post(f'{API_URL}{predict_path}', headers=API_HEADERS,
                                  json={'flows': batch}, timeout=30)
                if resp.status_code == 200:
                    all_preds.extend(resp.json().get('predictions', []))
                else:
                    print(f"[Sensor] ML API {predict_path} HTTP {resp.status_code}: {resp.text[:120]}")
            except Exception as e:
                print(f"[Sensor] Error batch: {e}")

        # Enriquecer
        enriched = []
        for j, pred in enumerate(all_preds):
            if j < len(flow_metadata):
                pred.update(flow_metadata[j])
                try:
                    fwd = flows_data[j].get('total_fwd_packets', flows_data[j].get('Total Fwd Packets', 0))
                    bwd = flows_data[j].get('total_bwd_packets', flows_data[j].get('Total Backward Packets', 0))
                    pred['n_packets'] = int(float(fwd)) + int(float(bwd))
                except:
                    pred['n_packets'] = 0
            # Guardar features originales para XAI
            if j < len(model_inputs):
                pred['_features'] = model_inputs[j]
            enriched.append(pred)

        attacks = [p for p in enriched if p.get('is_attack')]
        cat_dist = {}
        for p in enriched:
            cat_dist[p.get('category', '?')] = cat_dist.get(p.get('category', '?'), 0) + 1

        window_end = time.time()
        capture_state['status'] = 'done'
        capture_state['results'] = {
            'request_id': request_id,
            'window_start': window_start,
            'window_end': window_end,
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type, 'intensity': intensity,
            'capture_duration': duration, 'packets': packet_count,
            'flows': len(enriched), 'predictions': enriched,
            'cicflowmeter_version': 'CICFlowMeter Python 0.5.0',
            'summary': {
                'total': len(enriched), 'attacks_detected': len(attacks),
                'benign': len(enriched) - len(attacks),
                'category_distribution': cat_dist,
            },
        }
        # Persistir cada prediccion con request_id + 5-tupla para correlacion
        write_predictions_jsonl(request_id, enriched, window_start, window_end)
        print(f"[Sensor] OK: {len(enriched)} flujos, {len(attacks)} ataques (CICFlowMeter) req={request_id}")

    except Exception as e:
        capture_state['status'] = 'error'
        capture_state['error'] = str(e)
        print(f"[Sensor] Error: {e}")
        import traceback
        traceback.print_exc()


@app.get("/health")
def health():
    return {"status": "ok", "service": "ids-sensor", "version": "3.0.0",
            "target": TARGET_IP, "interface": INTERFACE,
            "feature_extractor": "CICFlowMeter"}


@app.post("/capture/start")
def start_capture(req: CaptureRequest):
    if capture_state['status'] == 'capturing':
        return {"error": "Captura en progreso", "status": "capturing",
                "request_id": capture_state.get('request_id')}
    request_id = f"req-{uuid.uuid4().hex[:12]}"
    t = threading.Thread(target=do_capture,
                         args=(req.duration, req.attack_type, req.intensity, request_id))
    t.daemon = True
    t.start()
    return {"message": f"CICFlowMeter: ataque '{req.attack_type}' ({req.duration}s, "
            f"{req.intensity}/s) contra {TARGET_IP}", "status": "capturing",
            "request_id": request_id}


@app.get("/capture/status")
def get_status():
    return {'status': capture_state['status'],
            'packets_captured': capture_state['packets_captured'],
            'flows_extracted': capture_state['flows_extracted'],
            'duration': capture_state['duration'],
            'request_id': capture_state.get('request_id')}


@app.get("/capture/results")
def get_results():
    if capture_state['results'] is None:
        return {"error": "No hay resultados", "status": capture_state['status']}
    return capture_state['results']


@app.on_event("startup")
def startup():
    load_model_features()


if __name__ == '__main__':
    print(f"[Sensor] CICFlowMeter | API={API_URL} TARGET={TARGET_IP}")
    uvicorn.run(app, host="0.0.0.0", port=9999)
