import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export type RiskLevel = "high" | "medium" | "low" | "unknown";

export function getRiskLevel(score: number): RiskLevel {
  if (score >= 0.7) return "high";
  if (score >= 0.4) return "medium";
  if (score > 0) return "low";
  return "unknown";
}

export function getRiskBadgeColor(level: RiskLevel) {
  return {
    high: "bg-red-500/10 text-red-400 ring-1 ring-red-500/20",
    medium: "bg-yellow-500/10 text-yellow-400 ring-1 ring-yellow-500/20",
    low: "bg-green-500/10 text-green-400 ring-1 ring-green-500/20",
    unknown: "bg-zinc-500/10 text-zinc-400 ring-1 ring-zinc-500/20",
  }[level];
}
