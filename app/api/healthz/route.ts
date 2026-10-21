import { config } from "@/src/server/config";
import { contractVersion } from "@/src/server/db/api";
import { json } from "@/src/server/http/respond";

// Liveness only: reports whether the expected control contract is reachable. No data.
export async function GET() {
  const ok = (await contractVersion()) === config.contractVersion;
  return json({ ok }, ok ? 200 : 503);
}
