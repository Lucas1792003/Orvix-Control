import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";

export const metadata: Metadata = {
  title: "Orvix Control",
  description: "Platform admin console (local development)",
  robots: { index: false, follow: false },
  referrer: "no-referrer",
};

// Every page is rendered per request so the CSP nonce applies and no auth decision is ever cached.
export const dynamic = "force-dynamic";

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  await headers();
  return (
    <html lang="en">
      <body className="min-h-screen font-sans antialiased">{children}</body>
    </html>
  );
}
