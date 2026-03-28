# Phase 3 Complete: FastAPI Inference Server + GitHub Actions

**Status:** COMPLETED
**Date:** 2026-03-28
**Timeline:** Week 3 complete

---

## Deliverables

### 1. Inference Engine (`inference.py`)
- Loads XGBoost + Random Forest + StandardScaler from disk
- Ensemble voting (average of both model probabilities)
- Confidence scoring (model agreement spread)
- Full feature breakdown in response
- Singleton pattern for FastAPI reuse (`get_predictor()`)

### 2. FastAPI Server (`api.py`)
Three production endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Check loaded models, version |
| `/predict` | POST | Diff → risk score + features |
| `/explain` | POST | Diff → ranked risk factors + plain-English |

CORS enabled. Pydantic request/response validation.

### 3. GitHub Actions Workflow (`.github/workflows/vuln-predict.yml`)
- Triggers on every PR (opened, sync, reopened)
- Extracts git diff from PR
- Calls `/predict` API
- Posts formatted comment on PR with:
  - Risk score + percentage
  - Vulnerable/benign prediction
  - Dangerous API flag
  - Code entropy score
  - Recommendations if risky
  - Deletes old bot comments to avoid spam

### 4. Vercel Deployment Config (`vercel.json`)
- Routes all traffic to FastAPI via `@vercel/python`
- Ready for `vercel deploy`

---

## API Test Results

```
[HEALTH]  status=ok  models=[xgboost, random_forest]  features=11
[PREDICT] vulnerable  73.1%  confidence=high  (strcpy diff)
[EXPLAIN] vulnerable  66.9%  "Dangerous API usage detected"
```

---

## GitHub Actions PR Comment Format

```
## Red  Vulnerability Risk: High Risk

| Metric          | Value       |
|-----------------|-------------|
| Risk Score      | 73.1%       |
| Prediction      | Vulnerable  |
| Confidence      | high        |
| Dangerous APIs  | Detected    |
| Code Entropy    | 0.964       |

### Recommendations
- Review all API calls in this diff for unsafe patterns
- Run `python advanced_predictor/inference.py` locally
- Consider requesting an additional security review
```

---

## Setup Instructions for Users

```bash
# 1. Add secret to GitHub repo
#    Settings → Secrets → PREDICTOR_API_URL = https://your-api.vercel.app

# 2. Deploy API to Vercel
vercel deploy --prod

# 3. Workflow fires automatically on every PR
```

---

## Files Created

```
vuln-agent/
├── advanced_predictor/
│   ├── inference.py                 [DONE] Load models + predict
│   └── api.py                       [DONE] FastAPI /predict /explain /health
├── .github/
│   └── workflows/
│       └── vuln-predict.yml         [DONE] PR risk analysis
└── vercel.json                      [DONE] Vercel deployment config
```

---

## Next Phase: Next.js Dashboard (Phase 4)

- Upload diff or paste git URL → get prediction
- SHAP visualization charts
- Prediction history + 30-day trend
- GitHub token setup guide
- API key management

