import { listAudit, requirePage } from "@/src/server/services/console";
import { callApi } from "@/src/server/db/api";
import { StatusBadge, fmtTime } from "@/src/ui/Status";
import { AuditTools, type Anchor } from "./AuditTools";

export default async function AuditPage({ searchParams }: { searchParams: Promise<{ before?: string }> }) {
  const s = await requirePage();
  const before = Number((await searchParams).before);
  const { scope, events } = await listAudit(s, 50, Number.isInteger(before) && before > 0 ? before : null);
  const last = events.at(-1)?.seq;
  const anchors = s.role === "owner" ? await callApi("api_anchor_list", [s.token]) : null;
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Audit log</h1>
        <p className="mt-1 text-sm text-muted">
          Append-only and hash-chained. {scope === "all" ? "Showing all events." : "Platform admins see their own actions only."}
        </p>
      </div>
      {s.role === "owner" && <AuditTools csrf={s.csrf} anchors={anchors?.ok ? (anchors.anchors as Anchor[]) : []} />}
      <div className="overflow-x-auto rounded-lg border border-line bg-panel">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="border-b border-line text-xs text-muted">
            <tr><th className="px-3 py-2 font-medium">Seq</th><th className="px-3 py-2 font-medium">Time</th><th className="px-3 py-2 font-medium">Actor</th><th className="px-3 py-2 font-medium">Action</th><th className="px-3 py-2 font-medium">Outcome</th><th className="px-3 py-2 font-medium">Target / reason</th><th className="px-3 py-2 font-medium">Hash</th></tr>
          </thead>
          <tbody className="divide-y divide-line">
            {events.map((e) => (
              <tr key={e.seq}>
                <td className="px-3 py-1.5 font-mono text-xs">{e.seq}</td>
                <td className="px-3 py-1.5 text-xs text-muted">{fmtTime(e.occurred_at)}</td>
                <td className="px-3 py-1.5 text-xs">{e.actor_label ?? e.actor_type}</td>
                <td className="px-3 py-1.5 font-mono text-xs">{e.action}</td>
                <td className="px-3 py-1.5"><StatusBadge value={e.outcome} /></td>
                <td className="px-3 py-1.5 text-xs text-muted">{[e.target_type, e.target_id?.slice(0, 8), e.reason_code].filter(Boolean).join(" · ")}</td>
                <td className="px-3 py-1.5 font-mono text-xs text-muted">{e.row_hash}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {last !== undefined && last > 0 && events.length === 50 && (
        <a href={`/audit?before=${last}`} className="text-sm underline">Older events</a>
      )}
    </div>
  );
}
