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
        { source: "/api/:path*", destination: `${backendUrl}/api/:path*` },
        { source: "/auth/:path*", destination: `${backendUrl}/auth/:path*` },
      ]
    },
  }),
}

export default nextConfig
