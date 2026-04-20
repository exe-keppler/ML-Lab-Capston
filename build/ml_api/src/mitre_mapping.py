"""
Mapeo de categorías de ataque a MITRE ATT&CK.
Copia funcional del módulo original deploy/ml_api/src/mitre_mapping.py
"""

MITRE_MAP = {
    "Benign": {
        "category": "Benign",
        "description": "Trafico de red normal/legitimo",
        "tactics": [],
        "techniques": [],
    },
    "DoS": {
        "category": "Denial of Service",
        "description": "Ataques de denegacion de servicio",
        "tactics": [{"id": "TA0040", "name": "Impact"}],
        "techniques": [{"id": "T1499", "name": "Endpoint Denial of Service"}],
    },
    "DDoS": {
        "category": "Distributed Denial of Service",
        "description": "Ataques distribuidos de denegacion de servicio",
        "tactics": [{"id": "TA0040", "name": "Impact"}],
        "techniques": [{"id": "T1498", "name": "Network Denial of Service"}],
    },
    "Brute Force": {
        "category": "Brute Force / Credential Access",
        "description": "Intentos de acceso por fuerza bruta",
        "tactics": [{"id": "TA0006", "name": "Credential Access"}],
        "techniques": [{"id": "T1110", "name": "Brute Force"}],
    },
    "Web Attack": {
        "category": "Web Application Attack",
        "description": "Ataques a aplicaciones web (XSS, SQLi, brute force)",
        "tactics": [{"id": "TA0001", "name": "Initial Access"}],
        "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    },
    "Reconnaissance": {
        "category": "Reconnaissance / Discovery",
        "description": "Escaneo de red, bots, movimiento lateral",
        "tactics": [{"id": "TA0043", "name": "Reconnaissance"}, {"id": "TA0007", "name": "Discovery"}],
        "techniques": [{"id": "T1046", "name": "Network Service Discovery"}],
    },
}


def get_mitre_info(category: str) -> dict:
    return MITRE_MAP.get(category, MITRE_MAP["Benign"])


def get_all_mappings() -> dict:
    return MITRE_MAP
