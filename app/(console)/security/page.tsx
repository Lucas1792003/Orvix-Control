import { requirePage } from "@/src/server/services/console";
import { callApi } from "@/src/server/db/api";
import { PasskeyPanel, type Cred } from "./PasskeyPanel";
import { RecoveryPanel, type RecoveryRequest } from "./RecoveryPanel";

export default async function SecurityPage() {
  const s = await requirePage();
  const creds = await callApi("api_credential_list", [s.token]);
  const recovery = await callApi("api_recovery_list", [s.token]);
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold">Security</h1>
        <p className="mt-1 text-sm text-muted">Your passkeys. Adding or removing one requires confirming with an existing passkey.</p>
      </div>
      <PasskeyPanel csrf={s.csrf} identityId={s.identityId} credentials={creds.ok ? (creds.credentials as Cred[]) : []} />
      {recovery.ok && (s.role === "owner" || (recovery.requests as RecoveryRequest[]).length > 0) && (
        <RecoveryPanel csrf={s.csrf} requests={recovery.ok ? (recovery.requests as RecoveryRequest[]) : []} />
      )}
    </div>
  );
}
