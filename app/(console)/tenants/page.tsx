import Link from "next/link";
import { listTenants, requirePage } from "@/src/server/services/console";
import { StatusBadge, fmtTime } from "@/src/ui/Status";

export default async function TenantsPage() {
  const s = await requirePage();
  const tenants = await listTenants(s);
  return (
    <div>
      <h1 className="text-xl font-semibold">Tenants</h1>
      <p className="mt-1 text-sm text-muted">Synthetic records in the lifecycle model. Metadata only; no tenant business data exists here.</p>
      <div className="mt-6 overflow-x-auto rounded-lg border border-line bg-panel">
        <table className="w-full min-w-[640px] text-left text-sm">
          <thead className="border-b border-line text-xs text-muted">
            <tr><th className="px-4 py-2 font-medium">Name</th><th className="px-4 py-2 font-medium">Status</th><th className="px-4 py-2 font-medium">Shops</th><th className="px-4 py-2 font-medium">Users</th><th className="px-4 py-2 font-medium">Admin MFA</th><th className="px-4 py-2 font-medium">Since</th></tr>
          </thead>
          <tbody className="divide-y divide-line">
            {tenants.map((t) => (
              <tr key={t.id}>
                <td className="px-4 py-2"><Link href={`/tenants/${t.id}`} className="font-medium underline-offset-2 hover:underline">{t.display_name}</Link><div className="font-mono text-xs text-muted">{t.slug}</div></td>
                <td className="px-4 py-2"><StatusBadge value={t.status} /></td>
                <td className="px-4 py-2 tabular-nums">{t.shop_count}</td>
                <td className="px-4 py-2 tabular-nums">{t.user_count}</td>
                <td className="px-4 py-2">{t.admin_mfa_verified ? "verified" : <span className="text-warn">not verified</span>}</td>
                <td className="px-4 py-2 text-xs text-muted">{fmtTime(t.status_changed_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
