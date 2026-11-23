import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Cloudflare Turnstile "are you human" gate, shown once when a visitor first opens the site.
 *
 * The gate is on only when both keys are set (Cloudflare dashboard → Turnstile → add site):
 *   TURNSTILE_SITE_KEY    (public, rendered into the challenge page by src/proxy.ts)
 *   TURNSTILE_SECRET_KEY  (server only, used to verify tokens and sign the cookie)
 *
 * After a passed challenge the visitor gets a signed session cookie, so they are not asked
 * again until they close the browser (or VERIFIED_FOR_MS passes).
 *
 * Shared by src/proxy.ts and the /api/turnstile route, so no "server-only" import here.
 */

export const HUMAN_COOKIE = "stn_hv";
const VERIFIED_FOR_MS = 24 * 60 * 60 * 1000;

function read(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

export function turnstileKeys(): { siteKey: string; secretKey: string } | null {
  const siteKey = read("TURNSTILE_SITE_KEY");
  const secretKey = read("TURNSTILE_SECRET_KEY");
  return siteKey && secretKey ? { siteKey, secretKey } : null;
}

function sign(issuedAt: string, secretKey: string): string {
  // Separate key from the raw Turnstile secret, so the cookie MAC is never the secret itself.
  const key = createHmac("sha256", secretKey).update("stn-human-cookie-v1").digest();
  return createHmac("sha256", key).update(issuedAt).digest("base64url");
}

/** Cookie value: "<issuedAtMs>.<hmac>". */
export function createHumanCookie(secretKey: string, now = Date.now()): string {
  const issuedAt = String(now);
  return `${issuedAt}.${sign(issuedAt, secretKey)}`;
}

export function isValidHumanCookie(value: string | undefined, secretKey: string, now = Date.now()): boolean {
  if (!value) return false;
  const [issuedAt, mac] = value.split(".");
  if (!issuedAt || !mac || !/^\d{1,15}$/.test(issuedAt)) return false;
  const age = now - Number(issuedAt);
  if (age < 0 || age > VERIFIED_FOR_MS) return false;
  const expected = Buffer.from(sign(issuedAt, secretKey));
  const actual = Buffer.from(mac);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/** Checks a widget token with Cloudflare. https://developers.cloudflare.com/turnstile/get-started/server-side-validation/ */
export async function verifyTurnstileToken(token: string, secretKey: string, remoteIp?: string): Promise<boolean> {
  const body = new URLSearchParams({ secret: secretKey, response: token });
  if (remoteIp) body.set("remoteip", remoteIp);
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body,
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return false;
    const data = (await res.json()) as { success?: boolean };
    return data.success === true;
  } catch {
    return false;
  }
}

/**
 * Host name the visitor actually used. Behind a reverse proxy (Hostinger runs `next start` behind
 * its CDN), `request.nextUrl` reports the bind address (e.g. 0.0.0.0), so prefer the forwarded /
 * Host headers.
 */
export function requestHost(headers: Headers, fallback: string): string {
  const raw = headers.get("x-forwarded-host")?.split(",")[0]?.trim() || headers.get("host")?.trim();
  return raw || fallback;
}
