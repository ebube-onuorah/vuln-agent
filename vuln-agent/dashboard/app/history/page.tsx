"use client";

import { Shield, Trash2, AlertTriangle, CheckCircle, Clock } from "lucide-react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { usePredictionHistory } from "@/hooks/usePredictionHistory";
import { cn, getRiskLevel, getRiskBadgeColor } from "@/lib/utils";

export default function HistoryPage() {
  const { history, clearHistory } = usePredictionHistory();

  const stats = {
    total: history.length,
    vulnerable: history.filter((h) => h.prediction === "vulnerable").length,
    avgRisk: history.length
      ? (history.reduce((s, h) => s + h.risk_score, 0) / history.length * 100).toFixed(1)
      : "0",
  };

  return (
    <div className="min-h-screen bg-zinc-950">
      <header className="border-b border-zinc-800 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="flex items-center gap-2 text-zinc-400 hover:text-zinc-200 transition-colors text-sm">
              <Shield className="w-5 h-5 text-blue-400" />
              <span className="font-semibold text-zinc-100">VulnPredictor</span>
            </Link>
            <span className="text-zinc-700">/</span>
            <span className="text-sm text-zinc-400">History</span>
          </div>
          {history.length > 0 && (
            <Button variant="ghost" size="sm" onClick={clearHistory} className="text-zinc-500 hover:text-red-400">
              <Trash2 className="w-4 h-4 mr-2" />
              Clear
            </Button>
          )}
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-10">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-zinc-100 mb-1">Prediction History</h1>
          <p className="text-zinc-400 text-sm">Stored locally in your browser.</p>
        </div>

        {/* Stats */}
        {history.length > 0 && (
          <div className="grid grid-cols-3 gap-4 mb-8">
            {[
              { label: "Total Scans", value: stats.total },
              { label: "Vulnerable", value: stats.vulnerable, highlight: stats.vulnerable > 0 },
              { label: "Avg Risk", value: `${stats.avgRisk}%` },
            ].map(({ label, value, highlight }) => (
              <Card key={label} className="border-zinc-800">
                <CardContent className="pt-4 pb-4">
                  <p className="text-xs text-zinc-500 mb-1">{label}</p>
                  <p className={cn("text-2xl font-semibold font-mono", highlight ? "text-red-400" : "text-zinc-100")}>
                    {value}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Entries */}
        {history.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 text-zinc-600">
            <Clock className="w-8 h-8 mb-3 opacity-40" />
            <p className="text-sm">No predictions yet.</p>
            <Link href="/" className="mt-3 text-sm text-blue-400 hover:text-blue-300 transition-colors">
              Run your first prediction →
            </Link>
          </div>
        ) : (
          <div className="space-y-3">
            {history.map((entry, i) => {
              const level = getRiskLevel(entry.risk_score);
              return (
                <Card key={entry.id} className="border-zinc-800 hover:border-zinc-700 transition-colors">
                  <CardContent className="py-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-center gap-3 min-w-0">
                        {level === "high" || level === "medium"
                          ? <AlertTriangle className={cn("w-4 h-4 shrink-0", level === "high" ? "text-red-400" : "text-yellow-400")} />
                          : <CheckCircle className="w-4 h-4 shrink-0 text-green-400" />
                        }
                        <div className="min-w-0">
                          <p className="text-sm text-zinc-300 font-mono truncate">
                            {entry.repo ?? "unknown repo"}
                          </p>
                          <p className="text-xs text-zinc-600 mt-0.5 font-mono truncate">
                            {entry.diff_preview}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Badge className={cn("font-mono text-xs", getRiskBadgeColor(level))}>
                          {entry.risk_percent}
                        </Badge>
                        {entry.has_dangerous_apis && (
                          <Badge variant="destructive" className="text-xs">⚠ API</Badge>
                        )}
                      </div>
                    </div>
                    {i < history.length - 1 && <Separator className="mt-3 bg-zinc-800/50" />}
                    <p className="text-xs text-zinc-700 mt-2">
                      {new Date(entry.timestamp).toLocaleString()}
                    </p>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
}
