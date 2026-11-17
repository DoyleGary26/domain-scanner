import { getStripe, requestOrigin } from "@/lib/stripe";
import { ScanError, validateScanDomain } from "@/lib/scanner";

const PRODUCT_NAME = "Full Domain & Email Security Fix Report";

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
    return Response.json({ error: "Expected a JSON body with a domain string." }, { status: 400 });
  }

  let cleanDomain: string;
  try {
    cleanDomain = await validateScanDomain(domain);
  } catch (error) {
    if (error instanceof ScanError) {
      return Response.json({ error: error.message, code: error.code }, { status: error.status });
    }
    console.error(error);
    return Response.json({ error: "The domain could not be checked." }, { status: 500 });
  }

  try {
    const stripe = getStripe();
    const origin = requestOrigin(request);
    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: [
        {
          quantity: 1,
          price_data: {
            currency: "usd",
            unit_amount: 900,
            product_data: {
              name: PRODUCT_NAME,
              description: `For ${cleanDomain}`,
            },
          },
        },
      ],
      metadata: { domain: cleanDomain },
      success_url: `${origin}/?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${origin}/`,
    });

    if (!session.url) {
      return Response.json({ error: "Checkout could not be started." }, { status: 500 });
    }

    return Response.json({ url: session.url }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Checkout failed.");
    const message = error instanceof Error && error.message === "Stripe is not configured."
      ? error.message
      : "Checkout could not be started.";
    return Response.json({ error: message }, { status: 500 });
  }
}

function readDomain(payload: unknown): string | null {
  if (!payload || typeof payload !== "object" || !("domain" in payload)) return null;
  return typeof payload.domain === "string" ? payload.domain : null;
}
