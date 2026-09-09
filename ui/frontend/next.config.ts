import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export", // Single-binary plan: FastAPI serves static HTML from out/ + bundle's _next/ assets.
  images: {
    unoptimized: true, // Required when output is "export" (default loader needs a server).
  },
  allowedDevOrigins: ["127.0.0.1", "localhost"],
};

export default nextConfig;
