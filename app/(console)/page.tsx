import Link from "next/link";
import { listAudit, listTenants, requirePage } from "@/src/server/services/console";
import { MOCK_HEALTH } from "@/src/ui/mock";
import { StatusBadge, fmtTime } from "@/src/ui/Status";

const ORDER = ["active", "past_due", "suspended", "locked", "pending_activation", "invited", "provisioning", "draft", "abandoned", "archived"];

export default async function Overview() {
  const s = await requirePage();
  const [tenants, audit] = await Promise.all([listTenants(s), listAudit(s, 8)]);
  const counts = ORDER.map((st) => ({ st, n: tenants.filter((t) => t.status === st).length })).filter((c) => c.n > 0);
  const stuck = tenants.filter(
    (t) => ["draft", "provisioning", "invited"].includes(t.status) && Date.now() - new Date(t.status_changed_at).getTime() > 24 * 3600_000,
  );
  const mfaGaps = tenants.filter((t) => ["active", "past_due"].includes(t.status) && !t.admin_mfa_verified);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold">Overview</h1>
        <p className="mt-1 text-sm text-muted">Session ends after 15 minutes idle or at {fmtTime(s.absoluteExpiresAt)}.</p>
      </div>

      <section>
        <h2 className="text-sm font-medium text-muted">Tenants by status (synthetic)</h2>
        <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-5">
          {counts.map((c) => (
            <div key={c.st} className="rounded-lg border border-line bg-panel p-4">
              <div className="text-2xl font-semibold tabular-nums">{c.n}</div>
              <div className="mt-1"><StatusBadge value={c.st} /></div>
            </div>
          ))}
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2">
        <div className="rounded-lg border border-line bg-panel p-4">
          <h2 className="text-sm font-medium">Needs attention</h2>
          <ul className="mt-3 space-y-2 text-sm">
            {stuck.map((t) => (
              <li key={t.id}><Link className="underline" href={`/tenants/${t.id}`}>{t.display_name}</Link> <span className="text-muted">stuck in {t.status} &gt; 24 h</span></li>
            ))}
            {mfaGaps.map((t) => (
              <li key={t.id}><Link className="underline" href={`/tenants/${t.id}`}>{t.display_name}</Link> <span className="text-muted">admin MFA not verified</span></li>
            ))}
            {stuck.length + mfaGaps.length === 0 && <li className="text-muted">Nothing needs attention.</li>}
          </ul>
        </div>
        <div className="rounded-lg border border-line bg-panel p-4">
          <h2 className="text-sm font-medium">Operational health <span className="text-mock">(mock)</span></h2>
          <dl className="mt-3 grid grid-cols-2 gap-3 text-sm">
            {MOCK_HEALTH.tiles.map((t) => (
              <div key={t.label}><dt className="text-muted">{t.label}</dt><dd className="font-medium">{t.value}</dd></div>
            ))}
          </dl>
        </div>
      </section>

      <section>
        <div className="flex items-baseline justify-between">
          <h2 className="text-sm font-medium text-muted">Recent audit events {s.role === "admin" && "(your actions)"}</h2>
          <Link href="/audit" className="text-sm underline">All events</Link>
        </div>
        <ul className="mt-3 divide-y divide-line rounded-lg border border-line bg-panel text-sm">
          {audit.events.map((e) => (
            <li key={e.seq} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2">
              <span className="font-mono text-xs text-muted">#{e.seq}</span>
              <span className="font-mono text-xs">{e.action}</span>
              <StatusBadge value={e.outcome} />
              <span className="ml-auto text-xs text-muted">{fmtTime(e.occurred_at)}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
