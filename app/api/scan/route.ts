import { ScanError, scanDomain } from "@/lib/scanner";

export async function POST(request: Request) {
  const length = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(length) && length > 8192) {
    return Response.json({ error: "Request body is too large." }, { status: 400 });
  }

  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return Response.json({ error: "Request body must be JSON." }, { status: 400 });
  }

  const domain = readDomain(payload);
  if (domain === null) {
    return Response.json(
      { error: "Expected a JSON body with a domain string." },
      { status: 400 },
    );
  }

  try {
    const report = await scanDomain(domain);
    return Response.json(report, {
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    if (error instanceof ScanError) {
      return Response.json(
        { error: error.message, code: error.code },
        { status: error.status },
      );
    }
    console.error(error);
    return Response.json({ error: "The scan could not be completed." }, { status: 500 });
  }
}

function readDomain(payload: unknown): string | null {
  if (!payload || typeof payload !== "object" || !("domain" in payload)) return null;
  return typeof payload.domain === "string" ? payload.domain : null;
}
