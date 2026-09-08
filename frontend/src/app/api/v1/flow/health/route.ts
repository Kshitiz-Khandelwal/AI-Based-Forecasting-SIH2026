import { NextResponse } from "next/server";

const FLOW_INGEST_URL = process.env.FLOW_INGEST_URL || process.env.FLOW_SERVICE_URL || "http://localhost:8006";

export async function GET() {
  try {
    const res = await fetch(`${FLOW_INGEST_URL}/health`, {
      method: "GET",
      cache: "no-store",
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) {
      return NextResponse.json({ status: "degraded", service: "flow-ingest" }, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch (err: any) {
    return NextResponse.json(
      { error: true, status: "offline", service: "flow-ingest", message: err.message },
      { status: 502 }
    );
  }
}
