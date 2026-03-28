#!/bin/sh
set -e

MODEL_PATH="advanced_predictor/training/models/xgboost_model.pkl"

if [ ! -f "$MODEL_PATH" ]; then
  echo "[SETUP] No models found — training on sample data..."
  python advanced_predictor/training/create_sample_data.py
  python advanced_predictor/training/train.py
  echo "[SETUP] Training complete."
fi

exec uvicorn advanced_predictor.api:app --host 0.0.0.0 --port 8000
