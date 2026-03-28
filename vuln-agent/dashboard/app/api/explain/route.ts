import { NextRequest, NextResponse } from "next/server";

const API_URL = process.env.PREDICTOR_API_URL ?? "http://localhost:8000";

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);

  if (!body?.diff) {
    return NextResponse.json({ error: "diff required" }, { status: 400 });
  }

  const start = Date.now();

  try {
    const upstream = await fetch(`${API_URL}/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ diff: body.diff, model: body.model ?? "xgboost" }),
      signal: AbortSignal.timeout(30_000),
    });

    const data = await upstream.json();
    if (!upstream.ok) {
      console.error({ event: "explain_upstream_error", status: upstream.status, detail: data?.detail });
      return NextResponse.json({ error: data?.detail ?? "Upstream error" }, { status: upstream.status });
    }

    console.log({ event: "explain_ok", ms: Date.now() - start, prediction: data.prediction, model: body.model ?? "xgboost" });
    return NextResponse.json(data);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Failed to reach API";
    console.error({ event: "explain_error", ms: Date.now() - start, error: msg });
    return NextResponse.json({ error: msg }, { status: 502 });
  }
}
