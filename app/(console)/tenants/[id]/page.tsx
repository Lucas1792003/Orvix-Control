import Link from "next/link";
import { getTenant, requirePage } from "@/src/server/services/console";
import { StatusBadge, fmtTime } from "@/src/ui/Status";
import { TransitionPanel } from "./TransitionPanel";

export default async function TenantPage({ params }: { params: Promise<{ id: string }> }) {
  const s = await requirePage();
  const { id } = await params;
  const { tenant: t, history, transitions } = await getTenant(s, id);
  return (
    <div className="space-y-6">
      <Link href="/tenants" className="text-sm text-muted underline">← Tenants</Link>
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">{t.display_name}</h1>
        <StatusBadge value={t.status} />
        <span className="rounded bg-mock/10 px-1.5 py-0.5 text-xs text-mock">synthetic</span>
      </div>
      <dl className="grid grid-cols-2 gap-4 rounded-lg border border-line bg-panel p-4 text-sm sm:grid-cols-4">
        <div><dt className="text-muted">Slug</dt><dd className="font-mono">{t.slug}</dd></div>
        <div><dt className="text-muted">Shops</dt><dd>{t.shop_count}</dd></div>
        <div><dt className="text-muted">Users</dt><dd>{t.user_count}</dd></div>
        <div><dt className="text-muted">Admin MFA</dt><dd>{t.admin_mfa_verified ? "verified" : "not verified"}</dd></div>
        <div className="col-span-2"><dt className="text-muted">Status since</dt><dd>{fmtTime(t.status_changed_at)}{t.status_reason && ` · ${t.status_reason}`}</dd></div>
      </dl>
      <TransitionPanel tenantId={t.id} role={s.role} csrf={s.csrf} transitions={transitions} />
      <section>
        <h2 className="text-sm font-medium text-muted">Lifecycle history</h2>
        <ul className="mt-3 divide-y divide-line rounded-lg border border-line bg-panel text-sm">
          {history.length === 0 && <li className="px-4 py-3 text-muted">No transitions recorded in this environment.</li>}
          {history.map((h) => (
            <li key={h.audit_seq} className="flex flex-wrap gap-3 px-4 py-2">
              <StatusBadge value={h.from} /> → <StatusBadge value={h.to} />
              {h.reason_code && <span className="text-muted">{h.reason_code}</span>}
              <span className="ml-auto text-xs text-muted">audit #{h.audit_seq} · {fmtTime(h.changed_at)}</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
