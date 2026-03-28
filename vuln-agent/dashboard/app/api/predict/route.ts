import { NextRequest, NextResponse } from "next/server";

const API_URL = process.env.PREDICTOR_API_URL ?? "http://localhost:8000";
const API_KEY = process.env.PREDICTOR_API_KEY ?? "";

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);

  if (!body?.diff || typeof body.diff !== "string") {
    return NextResponse.json({ error: "diff field is required" }, { status: 400 });
  }

  const start = Date.now();

  try {
    const upstream = await fetch(`${API_URL}/predict`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(API_KEY && { "X-API-Key": API_KEY }),
      },
      body: JSON.stringify({
        diff: body.diff,
        repo: body.repo ?? null,
        commit_id: body.commit_id ?? null,
      }),
      signal: AbortSignal.timeout(30_000),
    });

    const data = await upstream.json();

    if (!upstream.ok) {
      console.error({ event: "predict_upstream_error", status: upstream.status, detail: data?.detail });
      return NextResponse.json(
        { error: data?.detail ?? "Upstream error" },
        { status: upstream.status }
      );
    }

    console.log({
      event: "predict_ok",
      ms: Date.now() - start,
      prediction: data.prediction,
      risk_score: data.risk_score,
      repo: body.repo ?? null,
    });

    return NextResponse.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to reach prediction API";
    console.error({ event: "predict_error", ms: Date.now() - start, error: message });
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
