import { NextResponse } from "next/server";

const API_URL = process.env.PREDICTOR_API_URL ?? "http://localhost:8000";

export async function GET() {
  try {
    const upstream = await fetch(`${API_URL}/metrics`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!upstream.ok) {
      return NextResponse.json({ error: "Metrics not available" }, { status: upstream.status });
    }
    return NextResponse.json(await upstream.json());
  } catch {
    return NextResponse.json({ error: "Could not reach API" }, { status: 502 });
  }
}
