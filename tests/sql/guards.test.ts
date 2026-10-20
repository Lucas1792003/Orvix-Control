// Migration-runner isolation guards (review P-F6).
import { describe, expect, it } from "vitest";
import pg from "pg";
import { loadDevEnv, superuserConfig } from "../../scripts/env";
import { migrate } from "../../scripts/migrator";

describe("migration runner guards", () => {
  it("refuses a database whose name is not an isolated orvix_control dev/test database", async () => {
    loadDevEnv();
    const admin = new pg.Client({ ...superuserConfig(), database: "orvix_control" });
    await admin.connect();
    await admin.query("DROP DATABASE IF EXISTS orvix_guard_probe WITH (FORCE)");
    await admin.query("CREATE DATABASE orvix_guard_probe");
    try {
      const c = new pg.Client({ ...superuserConfig(), database: "orvix_guard_probe" });
      await c.connect();
      try {
        await expect(migrate(c)).rejects.toThrow(/refusing/);
        const { rows } = await c.query("SELECT count(*)::int n FROM pg_namespace WHERE nspname IN ('control', 'control_ledger')");
        expect(rows[0].n).toBe(0);
      } finally {
        await c.end();
      }
    } finally {
      await admin.query("DROP DATABASE IF EXISTS orvix_guard_probe WITH (FORCE)");
      await admin.end();
    }
  });

  it("the dev cluster identifies itself as orvix-control-dev (checked by the runner and the server)", async () => {
    const c = new pg.Client({ ...superuserConfig(), database: "orvix_control" });
    await c.connect();
    try {
      expect((await c.query("SHOW cluster_name")).rows[0].cluster_name).toBe("orvix-control-dev");
    } finally {
      await c.end();
    }
  });
});
