"""
FastAPI Inference Server
Endpoints: /predict, /explain, /health

Run locally:
    pip install fastapi uvicorn
    uvicorn advanced_predictor.api:app --reload --port 8000

Deploy to Vercel: see vercel.json
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import sys
import os

# Allow imports from parent dir when run directly
sys.path.insert(0, os.path.dirname(__file__))

from inference import get_predictor
from explainability import get_explainer
from github_client import fetch_pr_diff, parse_pr_url
from auth import require_api_key

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Advanced Vulnerability Predictor",
    description="ML-powered code vulnerability prediction from git diffs",
    version="1.0.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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


class ScanGithubRequest(BaseModel):
    pr_url: str = Field(..., description="GitHub PR URL or 'owner/repo#123'")


class ScanGithubResponse(BaseModel):
    risk_score: float
    risk_percent: str
    confidence: str
    prediction: str
    model_scores: Dict[str, float]
    features: Dict[str, Any]
    pr: Dict[str, Any]


class MetricsResponse(BaseModel):
    dataset_size: int
    train_samples: int
    test_samples: int
    n_features: int
    feature_names: list
    models: Dict[str, Any]
    trained_on: str


class HealthResponse(BaseModel):
    status: str
    models_loaded: list
    n_features: int
    version: str


# ─── Endpoints ─────────────────────────────────────────────────────────────────

_AUTH = Depends(require_api_key)


@app.get("/metrics", response_model=MetricsResponse, tags=["System"])
async def metrics():
    """Return model training metrics and feature information."""
    import json
    from pathlib import Path

    metrics_path = Path(__file__).parent / "training" / "models" / "metrics.json"
    if not metrics_path.exists():
        raise HTTPException(status_code=404, detail="metrics.json not found — run train.py first.")

    data = json.loads(metrics_path.read_text())
    return MetricsResponse(
        dataset_size=data.get("dataset_size", 0),
        train_samples=data.get("train_samples", 0),
        test_samples=data.get("test_samples", 0),
        n_features=data.get("n_features", 11),
        feature_names=data.get("feature_names", []),
        models=data.get("models", {}),
        trained_on=data.get("timestamp", "unknown"),
    )


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


@app.post("/predict", response_model=PredictResponse, tags=["Prediction"], dependencies=[_AUTH])
@limiter.limit("30/minute")
async def predict(request: Request, body: PredictRequest):
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

    result = predictor.predict(body.diff)

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return PredictResponse(
        risk_score=result["risk_score"],
        risk_percent=result["risk_percent"],
        confidence=result["confidence"],
        prediction=result["prediction"],
        model_scores=result["model_scores"],
        features=result["features"],
        commit_id=body.commit_id,
        repo=body.repo,
    )


@app.post("/explain", response_model=ExplainResponse, tags=["Explainability"], dependencies=[_AUTH])
@limiter.limit("20/minute")
async def explain(request: Request, body: ExplainRequest):
    """
    Explain why a diff was flagged as risky.

    Returns ranked feature contributions and plain-English explanation.
    """
    explainer = get_explainer()
    result = explainer.explain(body.diff, model=body.model)

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


@app.post("/scan/github", response_model=ScanGithubResponse, tags=["Prediction"], dependencies=[_AUTH])
@limiter.limit("10/minute")
async def scan_github(request: Request, body: ScanGithubRequest):
    """
    Fetch a GitHub PR diff and predict its vulnerability risk.

    Accepts URLs like:
      - https://github.com/owner/repo/pull/123
      - owner/repo#123

    Public repos work without auth. Set GITHUB_TOKEN env var for private repos.
    """
    predictor = get_predictor()
    if not predictor.is_ready():
        raise HTTPException(status_code=503, detail="No models loaded.")

    try:
        pr_data = fetch_pr_diff(body.pr_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        msg = str(e)
        if "404" in msg:
            raise HTTPException(
                status_code=404,
                detail="PR not found. Check the URL and ensure the repo is public (or set GITHUB_TOKEN).",
            )
        if "403" in msg:
            raise HTTPException(
                status_code=429,
                detail="GitHub API rate limit hit. Set GITHUB_TOKEN to increase quota.",
            )
        raise HTTPException(status_code=502, detail=f"GitHub fetch failed: {msg}")

    result = predictor.predict(pr_data["diff"])
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return ScanGithubResponse(
        risk_score=result["risk_score"],
        risk_percent=result["risk_percent"],
        confidence=result["confidence"],
        prediction=result["prediction"],
        model_scores=result["model_scores"],
        features=result["features"],
        pr={
            "title": pr_data["title"],
            "url": body.pr_url,
            "repo": f"{pr_data['owner']}/{pr_data['repo']}",
            "pr_number": pr_data["pr_number"],
            "author": pr_data["author"],
            "base": pr_data["base"],
            "head": pr_data["head"],
            "files_count": pr_data["files_count"],
            "additions": pr_data["additions"],
            "deletions": pr_data["deletions"],
        },
    )


# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
