# label_conn_log.py - génération du dataset labellisé à partir de Zeek
import pandas as pd

log_path = "/usr/local/zeek/logs/current/conn.log"

# colonnes utilisées
columns = [
    'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
    'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
    'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
    'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
    'tunnel_parents'
]

df = pd.read_csv(log_path, sep='\t', comment='#', header=None)
df.columns = columns[:df.shape[1]]

# sélection des features utiles
features = ['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
df = df[features]

# labellisation simplifiée : ip publique = anomalie
def label_row(row):
    if row['id.resp_h'].startswith('192.') or row['id.resp_h'].startswith('10.') or row['id.resp_h'].startswith('172.'):
        return 0  # normal
    return 1  # anomalie

# application de la labellisation
df['label'] = df.apply(label_row, axis=1)

# sauvegarde du dataset labellisé
df.to_csv("labeled_conn.csv", index=False)
print("Dataset sauvegardé dans labeled_conn.csv")
