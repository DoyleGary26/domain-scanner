import Stripe from "stripe";

export function getStripe(): Stripe {
  const key = process.env.STRIPE_SECRET_KEY?.trim();
  if (!key) {
    throw new Error("Stripe is not configured.");
  }
  return new Stripe(key);
}

export class CheckoutOriginError extends Error {
  readonly status: 400 | 500;

  constructor(message: string, status: 400 | 500) {
    super(message);
    this.name = "CheckoutOriginError";
    this.status = status;
  }
}

function configuredOrigin(): string {
  const raw = process.env.APP_ORIGIN?.trim();
  if (!raw) {
    throw new CheckoutOriginError("App origin is not configured.", 500);
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new CheckoutOriginError("App origin is not configured.", 500);
  }

  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new CheckoutOriginError("App origin is not configured.", 500);
  }

  return url.origin;
}

export function requestOrigin(request: Request): string {
  const allowed = configuredOrigin();
  let incoming: string;
  try {
    incoming = new URL(request.url).origin;
  } catch {
    throw new CheckoutOriginError("Checkout origin is not allowed.", 400);
  }

  if (incoming !== allowed) {
    throw new CheckoutOriginError("Checkout origin is not allowed.", 400);
  }

  return allowed;
}
