import { buildFixGuide } from "@/lib/remediation";
import { getStripe } from "@/lib/stripe";
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

  const sessionId = readSessionId(payload);
  if (!sessionId) {
    return Response.json({ error: "Expected a checkout session id." }, { status: 400 });
  }

  let domain: string;
  try {
    const stripe = getStripe();
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const paidDomain = session.metadata?.domain?.trim();
    if (session.payment_status !== "paid" || !paidDomain) {
      return Response.json({ error: "Payment could not be verified." }, { status: 403 });
    }
    domain = paidDomain;
  } catch (error) {
    if (error instanceof Error && error.message === "Stripe is not configured.") {
      return Response.json({ error: error.message }, { status: 500 });
    }
    console.error(error instanceof Error ? error.message : "Checkout verification failed.");
    return Response.json({ error: "Payment could not be verified." }, { status: 403 });
  }

  try {
    const scanResult = await scanDomain(domain);
    const fixGuide = await buildFixGuide(scanResult);
    return Response.json({ scanResult, fixGuide }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    if (error instanceof ScanError) {
      return Response.json({ error: error.message, code: error.code }, { status: error.status });
    }
    console.error(error);
    return Response.json({ error: "The fix report could not be completed." }, { status: 500 });
  }
}

function readSessionId(payload: unknown): string | null {
  if (!payload || typeof payload !== "object" || !("sessionId" in payload)) return null;
  const sessionId = payload.sessionId;
  if (typeof sessionId !== "string") return null;
  const trimmed = sessionId.trim();
  if (!/^cs_[A-Za-z0-9_]{8,200}$/.test(trimmed)) return null;
  return trimmed;
}
