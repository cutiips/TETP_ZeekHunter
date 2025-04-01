# train_pipeline.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib
import os

# Chargement du dataset
df = pd.read_csv("labeled_conn.csv")

# Remplacement des '-' par 0
df = df.replace('-', 0)

# Conversion des colonnes numériques
for col in ['id.resp_p', 'duration', 'orig_bytes', 'resp_bytes']:
    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

# Encodage avec sauvegarde des encoders
encoders = {}
for col in ['id.orig_h', 'id.resp_h', 'proto', 'conn_state']:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    encoders[col] = le

# Features + Label
X = df.drop('label', axis=1)
y = df['label']

# Split train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Entraînement du modèle
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Évaluation
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# Sauvegarde modèle + encoders
os.makedirs("model", exist_ok=True)
joblib.dump(clf, "model/rf_model.joblib")
joblib.dump(encoders, "model/encoders.joblib")
print("Modèle et encoders sauvegardés dans le dossier 'model'")
