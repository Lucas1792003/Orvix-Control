"use client";
import { useState } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { postJson } from "@/src/ui/http";

export function EnrolForm({ token }: { token: string }) {
  const [state, setState] = useState<"idle" | "busy" | "done" | "error">(token ? "idle" : "error");
  const [account, setAccount] = useState<string | null>(null);

  async function register() {
    setState("busy");
    try {
      const o = await postJson("/api/auth/enroll/options", { token });
      if (!o.ok) throw new Error();
      const user = (o.options as { user?: { name?: string } }).user;
      setAccount(`${user?.name ?? "unknown"}${o.purpose === "recovery" ? " (recovery: all previous passkeys will be disabled)" : ""}`);
      const response = await startRegistration({ optionsJSON: o.options as never });
      const v = await postJson("/api/auth/enroll/verify", { token, response });
      if (!v.ok) throw new Error();
      setState("done");
    } catch {
      setState("error");
    }
  }

  if (state === "done") {
    return (
      <p className="mt-6 text-sm">
        Passkey registered. <a className="font-medium text-accent underline" href="/login">Sign in</a>
      </p>
    );
  }
  return (
    <div className="mt-6">
      {account && <p className="mb-3 text-sm">Enrolling a passkey for <span className="font-medium">{account}</span></p>}
      <button
        onClick={register}
        disabled={state === "busy" || !token}
        className="w-full rounded-md bg-accent px-4 py-2.5 text-sm font-medium text-white disabled:opacity-60 dark:text-black"
      >
        {state === "busy" ? "Waiting for passkey…" : "Register passkey"}
      </button>
      {state === "error" && (
        <p role="alert" className="mt-3 text-sm text-danger">
          This link is invalid, expired or already used, or registration was cancelled.
        </p>
      )}
    </div>
  );
}
