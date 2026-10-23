import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Allow the frontend to talk to a separately deployed backend
  // Set NEXT_PUBLIC_API_URL in Vercel dashboard to your backend URL
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000",
  },
};

export default nextConfig;
