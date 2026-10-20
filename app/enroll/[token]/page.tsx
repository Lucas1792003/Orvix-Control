import { EnrolForm } from "./EnrolForm";

export default async function EnrolPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  return (
    <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center px-4">
      <p className="text-xs font-medium uppercase tracking-widest text-muted">Orvix Control</p>
      <h1 className="mt-2 text-2xl font-semibold">Register your passkey</h1>
      <p className="mt-2 text-sm text-muted">
        This one-time link works once and expires (15 minutes for a first owner, 30 minutes for a recovery link). A recovery enrolment disables all of the account&apos;s previous passkeys. After registering, sign in.
      </p>
      <EnrolForm token={/^[0-9a-f]{64}$/.test(token) ? token : ""} />
    </main>
  );
}
