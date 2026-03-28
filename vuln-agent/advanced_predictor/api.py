"""
FastAPI Inference Server
Endpoints: /predict, /explain, /health

Run locally:
    pip install fastapi uvicorn
    uvicorn advanced_predictor.api:app --reload --port 8000

Deploy to Vercel: see vercel.json
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import sys
import os

# Allow imports from parent dir when run directly
sys.path.insert(0, os.path.dirname(__file__))

from inference import get_predictor
from explainability import get_explainer

app = FastAPI(
    title="Advanced Vulnerability Predictor",
    description="ML-powered code vulnerability prediction from git diffs",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ─── Request / Response Models ─────────────────────────────────────────────────

class PredictRequest(BaseModel):
    diff: str = Field(..., description="Git diff text to analyze", min_length=1)
    repo: Optional[str] = Field(None, description="Repository name (e.g. 'owner/repo')")
    author: Optional[str] = Field(None, description="Commit author username")
    commit_id: Optional[str] = Field(None, description="Commit hash (for tracking)")


class PredictResponse(BaseModel):
    risk_score: float
    risk_percent: str
    confidence: str
    prediction: str
    model_scores: Dict[str, float]
    features: Dict[str, Any]
    commit_id: Optional[str] = None
    repo: Optional[str] = None


class ExplainRequest(BaseModel):
    diff: str = Field(..., description="Git diff text to explain")
    model: str = Field("xgboost", description="Model to explain: 'xgboost' or 'random_forest'")


class ExplainResponse(BaseModel):
    prediction: str
    risk_score: float
    top_risk_factors: list
    feature_values: Dict[str, Any]
    explanation: str


class HealthResponse(BaseModel):
    status: str
    models_loaded: list
    n_features: int
    version: str


# ─── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """Check service health and loaded models."""
    predictor = get_predictor()
    models_loaded = []
    if predictor.xgb_model is not None:
        models_loaded.append("xgboost")
    if predictor.rf_model is not None:
        models_loaded.append("random_forest")

    return HealthResponse(
        status="ok" if predictor.is_ready() else "degraded",
        models_loaded=models_loaded,
        n_features=11,
        version="1.0.0",
    )


@app.post("/predict", response_model=PredictResponse, tags=["Prediction"])
async def predict(request: PredictRequest):
    """
    Predict vulnerability risk from a git diff.

    Returns a risk score (0-1), confidence, and feature breakdown.
    """
    predictor = get_predictor()

    if not predictor.is_ready():
        raise HTTPException(
            status_code=503,
            detail="No models loaded. Ensure model files exist in training/models/",
        )

    result = predictor.predict(request.diff)

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return PredictResponse(
        risk_score=result["risk_score"],
        risk_percent=result["risk_percent"],
        confidence=result["confidence"],
        prediction=result["prediction"],
        model_scores=result["model_scores"],
        features=result["features"],
        commit_id=request.commit_id,
        repo=request.repo,
    )


@app.post("/explain", response_model=ExplainResponse, tags=["Explainability"])
async def explain(request: ExplainRequest):
    """
    Explain why a diff was flagged as risky.

    Returns ranked feature contributions and plain-English explanation.
    """
    explainer = get_explainer()
    result = explainer.explain(request.diff, model=request.model)

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    # Map SHAP contributors to risk factor format
    risk_factors = [
        {
            "factor": c["description"],
            "shap_value": c["shap_value"],
            "feature_value": c["feature_value"],
            "severity": "high" if c["magnitude"] > 0.3 else "medium" if c["magnitude"] > 0.1 else "low",
            "direction": c["direction"],
        }
        for c in result["top_contributors"]
        if c["direction"] == "increases_risk"
    ]

    return ExplainResponse(
        prediction=result["prediction"],
        risk_score=result["risk_score"],
        top_risk_factors=risk_factors,
        feature_values={c["feature"]: c["feature_value"] for c in result["all_contributions"]},
        explanation=result["plain_english"],
    )


# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
