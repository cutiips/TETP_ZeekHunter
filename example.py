# Pas exécutable, mais sert d'exemple de code

# ====================================================
# 1. Préparation du dataset (extraction des données de Zeek)
# ====================================================

import pandas as pd

# Lecture du fichier conn.log généré par Zeek
df = pd.read_csv("/usr/local/zeek/logs/current/conn.log", sep='\t', comment='#', header=None)

# Définition des colonnes du fichier log
columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
           'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
df.columns = columns[:df.shape[1]]

# Sélection des variables pertinentes (features)
features = ['id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'duration',
            'orig_bytes', 'resp_bytes', 'conn_state']
df = df[features]

# Labellisation simplifiée :
# Si l'IP de destination est privée => trafic normal (0)
# Sinon => trafic potentiellement anormal (1)
def label_row(row):
    if row['id.resp_h'].startswith(('192.', '10.', '172.')):
        return 0
    return 1

df['label'] = df.apply(label_row, axis=1)

# Sauvegarde du dataset labellisé
df.to_csv("labeled_conn.csv", index=False)


# ====================================================
# 2. Entraînement d'un modèle Random Forest
# ====================================================

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib

# Chargement du dataset
df = pd.read_csv("labeled_conn.csv").replace('-', 0)

# Conversion des variables numériques
for col in ['id.resp_p', 'duration', 'orig_bytes', 'resp_bytes']:
    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

# Encodage des variables catégorielles
encoders = {}
for col in ['id.orig_h', 'id.resp_h', 'proto', 'conn_state']:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    encoders[col] = le

# Séparation du jeu d'entraînement et du jeu de test
X = df.drop('label', axis=1)
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Entraînement du modèle Random Forest
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Sauvegarde du modèle et des encoders
joblib.dump(clf, "model/rf_model.joblib")
joblib.dump(encoders, "model/encoders.joblib")


# ====================================================
# 3. Prédiction sur de nouveaux logs Zeek
# ====================================================

import pandas as pd
import joblib

# Chargement du modèle et des encoders
clf = joblib.load("model/rf_model.joblib")
encoders = joblib.load("model/encoders.joblib")

# Lecture d'un nouveau fichier conn.log
df = pd.read_csv("/usr/local/zeek/logs/current/conn.log", sep='\t', comment='#', header=None)
columns = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
           'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
df.columns = columns[:df.shape[1]]

# Préparation des features
df = df[features].replace('-', 0)

# Conversion numérique
for col in ['id.resp_p', 'duration', 'orig_bytes', 'resp_bytes']:
    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

# Encodage identique à l'entraînement
for col in ['id.orig_h', 'id.resp_h', 'proto', 'conn_state']:
    df[col] = encoders[col].transform(df[col].astype(str).where(df[col] != '', '0'))

# Prédictions du modèle
df['prediction'] = clf.predict(df)

# Affichage des connexions détectées comme suspectes
print(df[df['prediction'] == 1])
