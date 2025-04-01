# Anomaly detection on Zeek network logs using Random Forest

## 🔍 Description

This Proof of Concept (POC) offers an external and flexible anomaly detection pipeline dedicated to Zeek logs. It allows to preprocess network connection logs (`conn.log`), train a Random Forest classifier on labeled data, and predict anomalies on live or recorded traffic.

## 🚀 Features

- Processes Zeek connection logs (`conn.log`)
- Automatically labels dataset for training
- Trains a Random Forest anomaly detection model
- Predicts anomalies on new network data
- Easy to adapt to different environments (scenarios, encoders, models)

## 🛠 Components

- `label_conn_log.py` : preprocesses Zeek logs and generates labeled datasets.
- `train_pipeline.py` : trains a Random Forest model.
- `predict_pipeline.py` : detects anomalies on new logs using the trained model.
- `model/` : stores trained models and encoders (not available here)

## 📦 Installation

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv -y

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

## 🟣 Usage

### Step 1 — Generate the labeled dataset
```bash
python label_conn_log.py
```

### Step 2 — Train the model
```bash
python train_pipeline.py
```

### Step 3 — Predict anomalies on new logs
```bash
python predict_pipeline.py
```

## ⚡ Notes

- Logs are collected directly from Zeek's `conn.log`.
- IP labeling is simplified : public IP traffic is considered suspicious.
- Feature selection and labeling can easily be adapted depending on the use case.
- For production, we recommend extending the preprocessing and model evaluation.
