import { requirePage } from "@/src/server/services/console";
import { MOCK_HEALTH } from "@/src/ui/mock";

export default async function HealthPage() {
  await requirePage();
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Operational health</h1>
        <p className="mt-1 text-sm text-mock">{MOCK_HEALTH.generatedNote}</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {MOCK_HEALTH.tiles.map((t) => (
          <div key={t.label} className="rounded-lg border border-dashed border-mock/50 bg-panel p-4">
            <div className="text-xs text-muted">{t.label}</div>
            <div className="mt-1 text-lg font-semibold">{t.value}</div>
            <div className="mt-1 text-xs text-muted">{t.hint}</div>
          </div>
        ))}
      </div>
      <section className="rounded-lg border border-dashed border-mock/50 bg-panel p-4">
        <h2 className="text-sm font-medium">Till versions (mock)</h2>
        <ul className="mt-2 text-sm">
          {MOCK_HEALTH.tillVersions.map((v) => <li key={v.version}>{v.version}: {v.tills} tills</li>)}
        </ul>
      </section>
    </div>
  );
}
