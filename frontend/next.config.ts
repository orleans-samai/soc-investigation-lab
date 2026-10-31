import type { NextConfig } from "next";

// Two build targets:
//  - default ("standalone"): Next server that proxies /api/* to FastAPI (Docker / local dev).
//  - NEXT_OUTPUT=export: static files served by the backend itself (desktop app, single origin).
const staticExport = process.env.NEXT_OUTPUT === "export";
// Read at build time (baked into the routes manifest) for the standalone target.
const backend = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = staticExport
  ? {
      output: "export",
      trailingSlash: true,
      images: { unoptimized: true },
    }
  : {
      output: "standalone",
      poweredByHeader: false,
      async rewrites() {
        return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
      },
      async headers() {
        return [
          {
            source: "/:path*",
            headers: [
              { key: "X-Content-Type-Options", value: "nosniff" },
              { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
              { key: "X-Frame-Options", value: "DENY" },
            ],
          },
        ];
      },
    };

export default nextConfig;
