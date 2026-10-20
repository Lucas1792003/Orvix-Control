import { contractVersion } from "@/src/server/db/api";
import { json } from "@/src/server/http/respond";

// Liveness only: reports whether the expected control contract is reachable. No data.
export async function GET() {
  const v = await contractVersion();
  return json({ ok: v === "orvix-control/0.5" }, v === "orvix-control/0.5" ? 200 : 503);
}
