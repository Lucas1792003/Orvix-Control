import { redirect } from "next/navigation";
import { getSession } from "@/src/server/auth/session";
import { LoginForm } from "./LoginForm";

export default async function LoginPage() {
  if (await getSession()) redirect("/");
  return (
    <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center px-4">
      <p className="text-xs font-medium uppercase tracking-widest text-muted">Orvix Control</p>
      <h1 className="mt-2 text-2xl font-semibold">Sign in with a passkey</h1>
      <p className="mt-2 text-sm text-muted">
        Platform operators only. There is no password. Your passkey must verify you (biometric or PIN).
      </p>
      <LoginForm />
      <p className="mt-8 text-xs text-muted">Local development build. Synthetic data only.</p>
    </main>
  );
}
