"use client";
import { useState } from "react";
import { startAuthentication } from "@simplewebauthn/browser";
import { ERROR_TEXT, postJson } from "@/src/ui/http";

export function LoginForm() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function signIn() {
    setBusy(true);
    setError(null);
    try {
      const o = await postJson("/api/auth/login/options", {});
      if (!o.ok) throw new Error(String(o.error));
      const response = await startAuthentication({ optionsJSON: o.options as never });
      const v = await postJson("/api/auth/login/verify", { response });
      if (!v.ok) throw new Error(String(v.error));
      window.location.assign("/");
    } catch (e) {
      const code = (e as Error).message;
      setError(ERROR_TEXT[code] ?? "Sign-in was cancelled or refused.");
      setBusy(false);
    }
  }

  return (
    <div className="mt-6">
      <button
        onClick={signIn}
        disabled={busy}
        className="w-full rounded-md bg-accent px-4 py-2.5 text-sm font-medium text-white disabled:opacity-60 dark:text-black"
      >
        {busy ? "Waiting for passkey…" : "Sign in with passkey"}
      </button>
      {error && <p role="alert" className="mt-3 text-sm text-danger">{error}</p>}
    </div>
  );
}
