"use client";

import { useState, useEffect, useCallback } from "react";

export interface HistoryEntry {
  id: string;
  timestamp: string;
  repo?: string;
  risk_score: number;
  risk_percent: string;
  prediction: string;
  confidence: string;
  has_dangerous_apis: boolean;
  diff_preview: string; // first 80 chars of diff
}

const STORAGE_KEY = "vulnpredictor_history";
const MAX_ENTRIES = 50;

export function usePredictionHistory() {
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) setHistory(JSON.parse(raw));
    } catch {
      // ignore
    }
  }, []);

  const addEntry = useCallback((entry: Omit<HistoryEntry, "id" | "timestamp">) => {
    const next: HistoryEntry = {
      ...entry,
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
    };
    setHistory((prev) => {
      const updated = [next, ...prev].slice(0, MAX_ENTRIES);
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // storage full
      }
      return updated;
    });
  }, []);

  const clearHistory = useCallback(() => {
    setHistory([]);
    localStorage.removeItem(STORAGE_KEY);
  }, []);

  return { history, addEntry, clearHistory };
}
