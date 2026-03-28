"use client";

import { useState } from "react";
import Link from "next/link";
import { Shield, AlertTriangle, CheckCircle, Loader2, GitBranch, Code2, History, Github, BarChart2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { cn, getRiskLevel, getRiskBadgeColor, type RiskLevel } from "@/lib/utils";
import { usePredictionHistory } from "@/hooks/usePredictionHistory";
import { ShapChart } from "@/components/ShapChart";

interface PredictResult {
  risk_score: number;
  risk_percent: string;
  confidence: string;
  prediction: string;
  model_scores: Record<string, number>;
  features: {
    lines_added: number;
    lines_deleted: number;
    files_changed: number;
    has_dangerous_apis: boolean;
    entropy: number;
    cyclomatic_complexity: number;
    language_type: number;
  };
  pr?: {
    title: string;
    url: string;
    repo: string;
    pr_number: number;
    author: string;
    base: string;
    head: string;
    files_count: number;
    additions: number;
    deletions: number;
  };
}

type InputMode = "diff" | "github";

const SAMPLE_RISKY = `--- a/utils.c
+++ b/utils.c
@@ -5,3 +5,5 @@
 void process(char *input) {
+    char buf[64];
+    strcpy(buf, input);
+    system(buf);
 }`;

const SAMPLE_SAFE = `--- a/app.py
+++ b/app.py
@@ -10,4 +10,6 @@
 def get_user(user_id: int):
+    if not isinstance(user_id, int):
+        raise ValueError("Invalid user_id")
     return db.query(User).filter_by(id=user_id).first()`;

export default function Home() {
  const [mode, setMode] = useState<InputMode>("diff");
  const [diff, setDiff] = useState("");
  const [prUrl, setPrUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PredictResult | null>(null);
  const [shap, setShap] = useState<{ top_risk_factors: { factor: string; shap_value: number; feature_value: number; direction: string; severity: string }[]; explanation: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { history, addEntry } = usePredictionHistory();

  async function handlePredict() {
    const isDiff = mode === "diff";
    if (isDiff && !diff.trim()) return;
    if (!isDiff && !prUrl.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setShap(null);

    try {
      let data: PredictResult;
      let diffForShap = diff;

      if (isDiff) {
        const res = await fetch("/api/predict", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ diff }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.error || "Prediction failed");
        }
        data = await res.json();
      } else {
        const res = await fetch("/api/scan-github", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pr_url: prUrl.trim() }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.error || "GitHub scan failed");
        }
        data = await res.json();
        diffForShap = "";
      }

      setResult(data);
      addEntry({
        repo: data.pr?.repo ?? undefined,
        risk_score: data.risk_score,
        risk_percent: data.risk_percent,
        prediction: data.prediction,
        confidence: data.confidence,
        has_dangerous_apis: data.features.has_dangerous_apis,
        diff_preview: data.pr
          ? `PR #${data.pr.pr_number}: ${data.pr.title}`.slice(0, 80)
          : diff.slice(0, 80).replace(/\n/g, " "),
      });

      // SHAP only available for paste-diff mode (we don't keep the full diff from GitHub in client)
      if (isDiff && diffForShap) {
        fetch("/api/explain", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ diff: diffForShap }),
        })
          .then((r) => r.ok ? r.json() : null)
          .then((s) => s && setShap(s))
          .catch(() => null);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  const riskLevel: RiskLevel = result ? getRiskLevel(result.risk_score) : "unknown";

  return (
    <div className="min-h-screen bg-zinc-950">
      {/* Header */}
      <header className="border-b border-zinc-800 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-blue-400" />
            <span className="font-semibold text-zinc-100">VulnPredictor</span>
            <Badge variant="secondary" className="text-xs">ML-Powered</Badge>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/history" className="flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-200 transition-colors">
              <History className="w-4 h-4" />
              History {history.length > 0 && <span className="text-xs text-zinc-600">({history.length})</span>}
            </Link>
            <Link href="/metrics" className="flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-200 transition-colors">
              <BarChart2 className="w-4 h-4" />
              Metrics
            </Link>
            <div className="flex items-center gap-1.5 text-sm text-zinc-600">
              <GitBranch className="w-4 h-4" />
              <span>GitHub Actions</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-10">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-zinc-100 mb-1">
            Code Vulnerability Predictor
          </h1>
          <p className="text-zinc-400 text-sm">
            Paste a git diff — XGBoost + Random Forest ensemble predicts vulnerability risk.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Input */}
          <div className="flex flex-col gap-3">
            {/* Mode tabs */}
            <div className="flex rounded-lg border border-zinc-800 overflow-hidden text-xs">
              <button
                onClick={() => { setMode("diff"); setResult(null); setShap(null); setError(null); }}
                className={cn(
                  "flex-1 flex items-center justify-center gap-1.5 py-2 transition-colors",
                  mode === "diff"
                    ? "bg-zinc-800 text-zinc-100"
                    : "text-zinc-500 hover:text-zinc-300"
                )}
              >
                <Code2 className="w-3.5 h-3.5" /> Paste Diff
              </button>
              <button
                onClick={() => { setMode("github"); setResult(null); setShap(null); setError(null); }}
                className={cn(
                  "flex-1 flex items-center justify-center gap-1.5 py-2 transition-colors border-l border-zinc-800",
                  mode === "github"
                    ? "bg-zinc-800 text-zinc-100"
                    : "text-zinc-500 hover:text-zinc-300"
                )}
              >
                <Github className="w-3.5 h-3.5" /> GitHub PR
              </button>
            </div>

            {mode === "diff" ? (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-zinc-500">Paste a git diff below</span>
                  <div className="flex gap-3 text-xs">
                    <button onClick={() => setDiff(SAMPLE_RISKY)} className="text-red-400 hover:text-red-300 transition-colors">
                      Load risky sample
                    </button>
                    <span className="text-zinc-700">·</span>
                    <button onClick={() => setDiff(SAMPLE_SAFE)} className="text-green-400 hover:text-green-300 transition-colors">
                      Load safe sample
                    </button>
                  </div>
                </div>
                <textarea
                  value={diff}
                  onChange={(e) => setDiff(e.target.value)}
                  placeholder={"Paste your git diff here...\n\n--- a/file.c\n+++ b/file.c\n@@ -1 +1,2 @@\n+    strcpy(buf, input);"}
                  className="h-64 w-full rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 text-sm text-zinc-200 placeholder:text-zinc-600 font-mono resize-none focus:outline-none focus:ring-1 focus:ring-blue-500/50"
                />
              </>
            ) : (
              <>
                <p className="text-xs text-zinc-500">
                  Enter a public GitHub PR URL. Private repos require{" "}
                  <code className="text-zinc-400">GITHUB_TOKEN</code> on the server.
                </p>
                <input
                  value={prUrl}
                  onChange={(e) => setPrUrl(e.target.value)}
                  placeholder="https://github.com/owner/repo/pull/123"
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 text-sm text-zinc-200 placeholder:text-zinc-600 font-mono focus:outline-none focus:ring-1 focus:ring-blue-500/50"
                />
                <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3 space-y-1 text-xs text-zinc-500">
                  <p className="text-zinc-400 font-medium mb-1">Also accepted:</p>
                  <p><code className="text-zinc-400">owner/repo#123</code></p>
                  <p><code className="text-zinc-400">github.com/owner/repo/pull/123</code></p>
                </div>
              </>
            )}

            <Button
              onClick={handlePredict}
              disabled={loading || (mode === "diff" ? !diff.trim() : !prUrl.trim())}
              className="w-full"
            >
              {loading ? (
                <><Loader2 className="w-4 h-4 animate-spin mr-2" />Analyzing...</>
              ) : mode === "diff" ? (
                <><Shield className="w-4 h-4 mr-2" />Predict Risk</>
              ) : (
                <><Github className="w-4 h-4 mr-2" />Scan PR</>
              )}
            </Button>

            {error && (
              <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-4 py-3">
                {error}
              </p>
            )}
          </div>

          {/* Results */}
          <div className="flex flex-col gap-3">
            {!result && !loading && (
              <div className="h-full flex items-center justify-center rounded-lg border border-dashed border-zinc-800 text-zinc-600 text-sm min-h-48">
                Results will appear here
              </div>
            )}

            {result && (
              <>
                {/* PR metadata */}
                {result.pr && (
                  <Card>
                    <CardContent className="pt-4 pb-3">
                      <div className="flex items-start gap-2">
                        <Github className="w-3.5 h-3.5 text-zinc-500 mt-0.5 shrink-0" />
                        <div className="min-w-0">
                          <p className="text-xs font-medium text-zinc-300 truncate">{result.pr.title}</p>
                          <p className="text-xs text-zinc-500 mt-0.5">
                            {result.pr.repo} · PR #{result.pr.pr_number}
                            {result.pr.author && <> · @{result.pr.author}</>}
                          </p>
                          <p className="text-xs text-zinc-600 mt-0.5 font-mono">
                            {result.pr.base} ← {result.pr.head} · {result.pr.files_count} files ·{" "}
                            <span className="text-green-600">+{result.pr.additions}</span>{" "}
                            <span className="text-red-600">-{result.pr.deletions}</span>
                          </p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Risk card */}
                <Card className={cn(
                  "border",
                  riskLevel === "high" && "border-red-800 bg-red-950/20",
                  riskLevel === "medium" && "border-yellow-800 bg-yellow-950/20",
                  riskLevel === "low" && "border-green-800 bg-green-950/20",
                )}>
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center justify-between text-base">
                      <div className="flex items-center gap-2">
                        {riskLevel === "high" && <AlertTriangle className="w-4 h-4 text-red-400" />}
                        {riskLevel === "medium" && <AlertTriangle className="w-4 h-4 text-yellow-400" />}
                        {riskLevel === "low" && <CheckCircle className="w-4 h-4 text-green-400" />}
                        <span className="capitalize text-zinc-100">{riskLevel} Risk</span>
                      </div>
                      <Badge className={cn("font-mono", getRiskBadgeColor(riskLevel))}>
                        {result.risk_percent}
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <Progress value={result.risk_score * 100} className="h-1.5" />
                    <div className="flex gap-4 text-xs text-zinc-500">
                      <span>Confidence: <span className="text-zinc-300">{result.confidence}</span></span>
                      <span>Prediction: <span className="text-zinc-300 capitalize">{result.prediction}</span></span>
                    </div>
                  </CardContent>
                </Card>

                {/* Model scores */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
                      Model Scores
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2.5">
                    {Object.entries(result.model_scores).map(([model, score]) => (
                      <div key={model} className="flex items-center gap-3">
                        <span className="text-xs text-zinc-500 w-28 font-mono capitalize">
                          {model.replace("_", " ")}
                        </span>
                        <Progress value={score * 100} className="flex-1 h-1.5" />
                        <span className="text-xs text-zinc-400 font-mono w-9 text-right">
                          {(score * 100).toFixed(0)}%
                        </span>
                      </div>
                    ))}
                  </CardContent>
                </Card>

                {/* Feature breakdown */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
                      Feature Breakdown
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-1.5 text-xs">
                      {[
                        ["Lines Added", result.features.lines_added],
                        ["Lines Deleted", result.features.lines_deleted],
                        ["Files Changed", result.features.files_changed],
                        ["Complexity", result.features.cyclomatic_complexity],
                        ["Entropy", result.features.entropy.toFixed(3)],
                        ["Dangerous APIs", result.features.has_dangerous_apis ? "⚠ Detected" : "None"],
                      ].map(([label, value], i, arr) => (
                        <div key={String(label)}>
                          <div className="flex justify-between items-center py-1">
                            <span className="text-zinc-500">{label}</span>
                            <span className={cn(
                              "font-mono",
                              label === "Dangerous APIs" && value === "⚠ Detected"
                                ? "text-red-400" : "text-zinc-300"
                            )}>
                              {String(value)}
                            </span>
                          </div>
                          {i < arr.length - 1 && <Separator className="bg-zinc-800" />}
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
                {/* SHAP explanation */}
                {shap && (
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
                        SHAP Explanation
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <p className="text-xs text-zinc-400 leading-relaxed">{shap.explanation}</p>
                      <ShapChart contributions={shap.top_risk_factors} />
                    </CardContent>
                  </Card>
                )}
              </>
            )}
          </div>
        </div>

        <footer className="mt-12 pt-6 border-t border-zinc-800 flex justify-between text-xs text-zinc-600">
          <span>XGBoost + Random Forest · 11 features · Ensemble voting</span>
          <span>Advanced VulnAgent — Portfolio Project</span>
        </footer>
      </main>
    </div>
  );
}
