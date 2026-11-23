import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV === "development";

/**
 * Content Security Policy.
 *
 * A nonce-based CSP would force every page to render per request and is incompatible with
 * Partial Prerendering (cacheComponents), so this is a static policy. Inline scripts are
 * allowed because Next.js streams its RSC payload in inline <script> tags; everything else
 * (where scripts load from, framing, form targets, plugins) is locked down.
 *
 * Third parties:
 * - tawk.to live chat (only loaded when NEXT_PUBLIC_TAWK_PROPERTY_ID is set)
 * - Google Maps embed on the Contact page
 * - Stripe Checkout (hosted page, reached by redirect after the checkout form posts)
 * - Cloudflare Turnstile, the one-time "are you human" check served by src/proxy.ts
 */
const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""} https://embed.tawk.to https://*.tawk.to https://challenges.cloudflare.com`,
  "style-src 'self' 'unsafe-inline' https://*.tawk.to https://fonts.googleapis.com",
  "img-src 'self' blob: data: https://*.tawk.to https://*.googleapis.com https://*.gstatic.com",
  "font-src 'self' data: https://*.tawk.to https://fonts.gstatic.com",
  "connect-src 'self' https://*.tawk.to wss://*.tawk.to",
  "frame-src https://www.google.com https://maps.google.com https://*.tawk.to https://challenges.cloudflare.com",
  "media-src 'self' https://*.tawk.to",
  "worker-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self' https://checkout.stripe.com",
  "frame-ancestors 'none'",
  ...(isDev ? [] : ["upgrade-insecure-requests"]),
].join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
  // Older browsers that ignore frame-ancestors.
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), browsing-topics=(), payment=(self)" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin-allow-popups" },
  ...(isDev ? [] : [{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" }]),
];

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  poweredByHeader: false,
  // PGlite (local development database) ships WebAssembly files; load it from node_modules as-is.
  serverExternalPackages: ["@electric-sql/pglite"],
  async headers() {
    return [{ source: "/(.*)", headers: securityHeaders }];
  },
};

export default nextConfig;
