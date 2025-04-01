# predict_pipeline.py
import pandas as pd
import numpy as np
import joblib

# Charger le modèle et les encoders
clf = joblib.load("model/rf_model.joblib")
encoders = joblib.load("model/encoders.joblib")

# Charger le log Zeek
log_path = "/usr/local/zeek/logs/current/conn.log"
df = pd.read_csv(log_path, sep='\t', comment='#', header=None)

# Colonnes
columns = [
    'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
    'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
    'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
    'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
    'tunnel_parents'
]
df.columns = columns[:df.shape[1]]

# Features
features = ['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
df = df[features]

# Remplace les '-' par 0
df = df.replace('-', 0)

# Conversion numérique
for col in ['id.resp_p', 'duration', 'orig_bytes', 'resp_bytes']:
    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

# Encodage avec les encoders du training
for col in ['id.orig_h', 'id.resp_h', 'proto', 'conn_state']:
    df[col] = encoders[col].transform(df[col].astype(str).where(df[col] != '', '0'))

# Prédictions
df['prediction'] = clf.predict(df)

# Afficher les connexions suspectes
suspicious = df[df['prediction'] == 1]
print("=== Connexions suspectes détectées ===")
print(suspicious)
