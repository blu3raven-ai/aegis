import type { NextConfig } from "next"

const isDev = process.env.NODE_ENV === "development"
const backendUrl = process.env.BACKEND_URL ?? "http://localhost:8000"

const nextConfig: NextConfig = {
  ...(isDev ? {} : { output: "export" }),
  trailingSlash: false,
  images: { unoptimized: true },
  ...(isDev && {
    async rewrites() {
      return [
        { source: "/code-scanning/api/:path*", destination: `${backendUrl}/code-scanning/api/:path*` },
        { source: "/dependencies/api/:path*", destination: `${backendUrl}/dependencies/api/:path*` },
        { source: "/container-scanning/api/:path*", destination: `${backendUrl}/container-scanning/api/:path*` },
        { source: "/secrets/api/:path*", destination: `${backendUrl}/secrets/api/:path*` },
        { source: "/notifications/api/:path*", destination: `${backendUrl}/notifications/api/:path*` },
        { source: "/settings/api/:path*", destination: `${backendUrl}/settings/api/:path*` },
        { source: "/settings/runners/:path*", destination: `${backendUrl}/settings/runners/:path*` },
        { source: "/license/api/:path*", destination: `${backendUrl}/license/api/:path*` },
        { source: "/api/:path*", destination: `${backendUrl}/api/:path*` },
        { source: "/auth/:path*", destination: `${backendUrl}/auth/:path*` },
      ]
    },
  }),
}

export default nextConfig
