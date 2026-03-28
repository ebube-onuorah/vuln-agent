"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Shield, BarChart2, ChevronLeft } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

interface ModelMetrics {
  precision: number;
  recall: number;
  f1: number;
  roc_auc: number;
  accuracy: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
}

interface MetricsData {
  dataset_size: number;
  train_samples: number;
  test_samples: number;
  n_features: number;
  feature_names: string[];
  models: Record<string, ModelMetrics>;
  trained_on: string;
}

const FEATURE_DESCRIPTIONS: Record<string, string> = {
  lines_added: "Lines of code added",
  lines_deleted: "Lines removed",
  lines_modified: "Lines modified (churn)",
  files_changed: "Files touched",
  cyclomatic_complexity: "Control flow complexity",
  avg_function_size: "Avg function length",
  has_dangerous_apis: "Dangerous API calls",
  entropy: "Shannon entropy",
  is_test_file: "Test file changes",
  language_type: "Language risk (C > Python > JS)",
  comment_ratio: "Comment density",
};

function pct(n: number) {
  return (n * 100).toFixed(1) + "%";
}

export default function MetricsPage() {
  const [data, setData] = useState<MetricsData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/metrics")
      .then((r) => r.ok ? r.json() : Promise.reject(r.statusText))
      .then(setData)
      .catch((e) => setError(String(e)));
  }, []);

  return (
    <div className="min-h-screen bg-zinc-950">
      <header className="border-b border-zinc-800 px-6 py-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-blue-400" />
            <span className="font-semibold text-zinc-100">VulnPredictor</span>
            <Badge variant="secondary" className="text-xs">ML-Powered</Badge>
          </div>
          <Link href="/" className="flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-200 transition-colors">
            <ChevronLeft className="w-4 h-4" /> Back
          </Link>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-10">
        <div className="mb-8 flex items-center gap-3">
          <BarChart2 className="w-5 h-5 text-zinc-400" />
          <div>
            <h1 className="text-2xl font-semibold text-zinc-100">Model Metrics</h1>
            <p className="text-zinc-400 text-sm mt-0.5">
              XGBoost + Random Forest training results and feature overview.
            </p>
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-red-900 bg-red-950/30 px-4 py-3 text-sm text-red-400 mb-6">
            {error === "Not Found"
              ? "Models not trained yet. Run: python advanced_predictor/training/train.py"
              : `Could not load metrics: ${error}`}
          </div>
        )}

        {data && (
          <div className="space-y-6">
            {/* Dataset summary */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
                  Training Dataset
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
                  {[
                    ["Total Samples", data.dataset_size],
                    ["Train Split", data.train_samples],
                    ["Test Split", data.test_samples],
                    ["Features", data.n_features],
                  ].map(([label, value]) => (
                    <div key={String(label)} className="rounded-lg bg-zinc-900 px-3 py-3">
                      <p className="text-2xl font-mono font-semibold text-zinc-100">{value}</p>
                      <p className="text-xs text-zinc-500 mt-0.5">{label}</p>
                    </div>
                  ))}
                </div>
                <p className="text-xs text-zinc-600 mt-3">
                  Trained {new Date(data.trained_on).toLocaleString()} · Synthetic data (swap big_vul.csv for production)
                </p>
              </CardContent>
            </Card>

            {/* Model metrics */}
            {Object.entries(data.models).map(([name, m]) => (
              <Card key={name}>
                <CardHeader className="pb-2">
                  <CardTitle className="flex items-center justify-between text-base">
                    <span className="capitalize text-zinc-100 font-mono">{name.replace("_", " ")}</span>
                    <Badge variant="secondary" className={cn(
                      "font-mono text-xs",
                      m.roc_auc >= 0.8 ? "bg-green-900/50 text-green-300" : "bg-yellow-900/50 text-yellow-300"
                    )}>
                      ROC-AUC {pct(m.roc_auc)}
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {[
                    ["Precision", m.precision],
                    ["Recall", m.recall],
                    ["F1 Score", m.f1],
                    ["Accuracy", m.accuracy],
                  ].map(([label, val]) => (
                    <div key={String(label)} className="flex items-center gap-3">
                      <span className="text-xs text-zinc-500 w-20">{label}</span>
                      <Progress value={(val as number) * 100} className="flex-1 h-1.5" />
                      <span className="text-xs font-mono text-zinc-300 w-12 text-right">{pct(val as number)}</span>
                    </div>
                  ))}
                  <Separator className="bg-zinc-800" />
                  <div className="grid grid-cols-4 gap-2 text-center text-xs">
                    {[
                      ["TP", m.true_positives, "text-green-400"],
                      ["FP", m.false_positives, "text-red-400"],
                      ["TN", m.true_negatives, "text-green-400"],
                      ["FN", m.false_negatives, "text-red-400"],
                    ].map(([label, val, color]) => (
                      <div key={String(label)} className="rounded bg-zinc-900 py-2">
                        <p className={cn("text-lg font-mono font-semibold", color)}>{val}</p>
                        <p className="text-zinc-600">{label}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))}

            {/* Feature list */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
                  11 Features
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1.5">
                  {data.feature_names.map((name, i) => (
                    <div key={name}>
                      <div className="flex items-center justify-between py-1 text-xs">
                        <div className="flex items-center gap-2">
                          <span className="text-zinc-600 font-mono w-5">{i + 1}.</span>
                          <code className="text-blue-400">{name}</code>
                        </div>
                        <span className="text-zinc-500 text-right max-w-[240px]">
                          {FEATURE_DESCRIPTIONS[name] ?? ""}
                        </span>
                      </div>
                      {i < data.feature_names.length - 1 && <Separator className="bg-zinc-800/60" />}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {!data && !error && (
          <div className="flex items-center justify-center h-48 text-zinc-600 text-sm">
            Loading metrics...
          </div>
        )}
      </main>
    </div>
  );
}
