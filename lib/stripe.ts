import Stripe from "stripe";

export function getStripe(): Stripe {
  const key = process.env.STRIPE_SECRET_KEY?.trim();
  if (!key) {
    throw new Error("Stripe is not configured.");
  }
  return new Stripe(key);
}

export function requestOrigin(request: Request): string {
  return new URL(request.url).origin;
}
