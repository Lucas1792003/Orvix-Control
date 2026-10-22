import Link from "next/link";
import { requirePage } from "@/src/server/services/console";
import { LogoutButton } from "./LogoutButton";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/tenants", label: "Tenants" },
  { href: "/pos-recovery", label: "POS recovery" },
  { href: "/audit", label: "Audit log" },
  { href: "/health", label: "Health" },
  { href: "/security", label: "Security" },
];

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const s = await requirePage();
  return (
    <div className="min-h-screen">
      <div className="bg-mock/10 px-4 py-1.5 text-center text-xs text-mock">
        Local development · synthetic tenants and mock health data only · POS reached only through its recovery_v1 operator interface, when installed
      </div>
      <header className="border-b border-line bg-panel">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <span className="font-semibold tracking-tight">Orvix Control</span>
          <nav className="flex flex-wrap gap-4 text-sm">
            {NAV.map((n) => (
              <Link key={n.href} href={n.href} className="text-muted hover:text-ink">{n.label}</Link>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            <span className="text-muted">
              {s.displayName} · <span className="font-medium text-ink">{s.role}</span>
            </span>
            <LogoutButton csrf={s.csrf} />
          </div>
        </div>
      </header>
      {(s.pendingCredentials > 0 || s.flaggedCredentials > 0) && (
        <div className="bg-danger/10 px-4 py-2 text-center text-sm text-danger">
          {s.pendingCredentials > 0 && "A passkey was added to your account recently and is still pending. If you did not add it, revoke it now. "}
          {s.flaggedCredentials > 0 && "A passkey was flagged as possibly cloned (signature counter went backwards). "}
          <Link href="/security" className="font-medium underline">Review passkeys</Link>
        </div>
      )}
      {s.activeCredentials < 2 && (
        <div className="bg-warn/10 px-4 py-2 text-center text-sm text-warn">
          You have only one passkey. If you lose it, recovery needs another owner.{" "}
          <Link href="/security" className="font-medium underline">Add a backup passkey</Link>
        </div>
      )}
      <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
    </div>
  );
}
