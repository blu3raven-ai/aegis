import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  serverExternalPackages: ["otplib", "qrcode"],
  async redirects() {
    return [
      { source: "/settings/sources/code-repositories", destination: "/sources/code-repositories", permanent: true },
      { source: "/settings/sources/code-repositories/:id", destination: "/sources/code-repositories/:id", permanent: true },
      { source: "/settings/sources/container-images", destination: "/sources/container-registry", permanent: true },
      { source: "/settings/sources/container-images/:id", destination: "/sources/container-registry/:id", permanent: true },
      { source: "/settings/sources/ci-cd-pipelines", destination: "/sources/code-repositories", permanent: true },
      { source: "/settings/sources/ci-cd-pipelines/:path*", destination: "/sources/code-repositories", permanent: true },
      { source: "/settings/dependencies", destination: "/dependencies/dashboard?tab=settings", permanent: false },
      { source: "/settings/containers", destination: "/containers/dashboard?tab=settings", permanent: false },
      { source: "/settings/code", destination: "/code/dashboard?tab=settings", permanent: false },
      { source: "/settings/secrets", destination: "/secrets/dashboard?tab=settings", permanent: false },
    ]
  },
  async rewrites() {
    return {
      beforeFiles: [],
    };
  },
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
          {
            key: "Content-Security-Policy",
            // NOTE: 'unsafe-inline' is required for Next.js hydration scripts.
            // Next.js injects inline <script> tags for page data and hydration
            // that cannot work without 'unsafe-inline' unless nonce-based CSP is
            // configured. Nonce support requires a custom server or middleware to
            // inject a per-request nonce into both the CSP header and every
            // inline script tag. Replace 'unsafe-inline' with nonces when
            // Next.js provides native nonce support or when a custom middleware
            // solution is implemented. Tracking: https://github.com/vercel/next.js/discussions/54907
            value: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
