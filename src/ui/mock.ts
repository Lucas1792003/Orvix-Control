// MOCK operational data for the initial dashboard. Invented values; nothing is measured or fetched.
// Real sources (POS heartbeat, backup status file, pg_stat_*) arrive with POS integration.
export const MOCK_HEALTH = {
  generatedNote: "Mock values: not connected to any server",
  tiles: [
    { label: "POS schema (mock)", value: "087", hint: "would come from app_backend_info()" },
    { label: "Last backup (mock)", value: "42 min ago", hint: "would come from backup-status file" },
    { label: "WAL archiver (mock)", value: "ok", hint: "pg_stat_archiver" },
    { label: "Suspension enforcement (mock)", value: "off", hint: "POS hook 102 not installed" },
  ],
  tillVersions: [
    { version: "1.0.16", tills: 3 },
    { version: "1.0.17", tills: 0 },
  ],
} as const;
