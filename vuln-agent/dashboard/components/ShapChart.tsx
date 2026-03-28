"use client";

import { cn } from "@/lib/utils";

interface ShapContribution {
  factor: string;
  shap_value: number;
  feature_value: number;
  direction: string;
  severity: string;
}

interface ShapChartProps {
  contributions: ShapContribution[];
}

export function ShapChart({ contributions }: ShapChartProps) {
  if (!contributions?.length) return null;

  const maxMagnitude = Math.max(...contributions.map((c) => Math.abs(c.shap_value)), 0.01);

  return (
    <div className="space-y-2">
      {contributions.map((c, i) => {
        const pct = (Math.abs(c.shap_value) / maxMagnitude) * 100;
        const isRisk = c.direction === "increases_risk";

        return (
          <div key={i} className="group">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-zinc-400 truncate max-w-[200px]" title={c.factor}>
                {c.factor}
              </span>
              <span className={cn(
                "text-xs font-mono tabular-nums",
                isRisk ? "text-red-400" : "text-green-400"
              )}>
                {isRisk ? "+" : ""}{c.shap_value.toFixed(3)}
              </span>
            </div>
            <div className="relative h-1.5 w-full rounded-full bg-zinc-800">
              <div
                className={cn(
                  "absolute top-0 h-full rounded-full transition-all",
                  isRisk ? "bg-red-500 left-0" : "bg-green-500 left-0"
                )}
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
      <p className="text-xs text-zinc-600 pt-1">
        Red = increases risk · Green = decreases risk · Width = magnitude
      </p>
    </div>
  );
}
