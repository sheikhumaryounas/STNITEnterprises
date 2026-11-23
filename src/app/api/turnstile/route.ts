import { NextResponse, type NextRequest } from "next/server";
import { HUMAN_COOKIE, createHumanCookie, requestHost, turnstileKeys, verifyTurnstileToken } from "@/server/human-check";

/**
 * The challenge page (src/proxy.ts) submits its form here once the Turnstile widget passes.
 * We check the token with Cloudflare, set the "verified" cookie and send the visitor straight
 * on to the page they opened, in one round trip.
 */

/** Only same-site paths, so this can't be used as an open redirect. */
function safeNext(value: FormDataEntryValue | null): string {
  if (typeof value !== "string" || value.length > 2048) return "/";
  if (!value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/";
  return value;
}

export async function POST(request: NextRequest) {
  // Compare hosts, not request.nextUrl.origin: behind Hostinger's proxy that is http://0.0.0.0:<port>.
  const origin = request.headers.get("origin");
  if (origin) {
    let originHost: string | null = null;
    try {
      originHost = new URL(origin).host;
    } catch {}
    if (originHost !== requestHost(request.headers, request.nextUrl.host)) {
      return new NextResponse("Forbidden", { status: 403 });
    }
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return new NextResponse("Bad request", { status: 400 });
  }
  const next = safeNext(form.get("next"));
  // Relative Location, so the browser stays on the host it is on (not the proxy's internal address).
  const response = new NextResponse(null, { status: 303, headers: { Location: next, "Cache-Control": "no-store" } });

  const keys = turnstileKeys();
  if (!keys) return response;

  const token = form.get("cf-turnstile-response");
  const remoteIp = request.headers.get("x-real-ip") ?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const passed =
    typeof token === "string" &&
    token.length > 0 &&
    token.length <= 4096 &&
    (await verifyTurnstileToken(token, keys.secretKey, remoteIp || undefined));

  // Failed: back to the same page, which shows the challenge again.
  if (!passed) return response;

  response.cookies.set(HUMAN_COOKIE, createHumanCookie(keys.secretKey), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    // No maxAge: a session cookie, so the check runs once per browser session.
  });
  return response;
}
