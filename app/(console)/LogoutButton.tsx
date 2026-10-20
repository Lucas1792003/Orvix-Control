"use client";
import { postJson } from "@/src/ui/http";

export function LogoutButton({ csrf }: { csrf: string }) {
  return (
    <button
      onClick={async () => {
        await postJson("/api/auth/logout", {}, csrf);
        window.location.assign("/login");
      }}
      className="rounded border border-line px-2.5 py-1 text-xs hover:border-ink"
    >
      Sign out
    </button>
  );
}
