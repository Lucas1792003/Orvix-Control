import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  // pg must stay a server-only external; it is never bundled for the browser.
  serverExternalPackages: ["pg"],
};

export default nextConfig;
