const TONE: Record<string, string> = {
  active: "text-ok border-ok/40",
  past_due: "text-warn border-warn/40",
  suspended: "text-danger border-danger/40",
  locked: "text-danger border-danger/40",
  archived: "text-muted border-line",
  abandoned: "text-muted border-line",
  draft: "text-muted border-line",
  provisioning: "text-accent border-accent/40",
  invited: "text-accent border-accent/40",
  pending_activation: "text-accent border-accent/40",
  success: "text-ok border-ok/40",
  denied: "text-danger border-danger/40",
  failed: "text-warn border-warn/40",
};

export function StatusBadge({ value }: { value: string }) {
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium ${TONE[value] ?? "text-muted border-line"}`}>
      {value.replace("_", " ")}
    </span>
  );
}

export function fmtTime(iso: string) {
  return new Date(iso).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }) + " UTC";
}
