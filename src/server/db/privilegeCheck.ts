// C1.3 M3/M4: database-privilege preconditions shared by the web server's startup check (src/server/db/api.ts), the
// sentinel and the tests. Run as the connecting role. Every field must be false / 0 for the role to be allowed to run.
export const CONTROL_DB_PATTERN = "^orvix_control(_e2e|_test_[a-z0-9]{6,16})?$";

// Built-in functions revoked from PUBLIC by migrations 207/208/210/217/221 (any of them executable = drift or an
// unhardened restore).
const REVOKED_BUILTINS = ["pg_advisory_lock", "pg_advisory_lock_shared", "pg_try_advisory_lock", "pg_try_advisory_lock_shared",
  "pg_advisory_xact_lock", "pg_advisory_xact_lock_shared", "pg_try_advisory_xact_lock", "pg_try_advisory_xact_lock_shared",
  "pg_advisory_unlock", "pg_advisory_unlock_shared", "pg_advisory_unlock_all", "lo_create", "lo_creat", "lo_from_bytea",
  "lo_import", "pg_notify", "pg_sleep", "pg_logical_emit_message", "txid_current", "pg_current_xact_id"];

const OWNERS = "'{control_auth,control_definer,control_audit_owner,control_schema_owner,control_watchdog_owner}'::text[]";

export const PRIVILEGE_CHECK_SQL = `
  SELECT has_database_privilege(current_user, current_database(), 'TEMP') AS temp_here,
         has_database_privilege(current_user, current_database(), 'CREATE') AS create_here,
         (SELECT d.datacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(d.datacl) a
                                              WHERE a.grantee = 0 AND a.privilege_type IN ('CONNECT', 'TEMPORARY', 'CREATE'))
            FROM pg_database d WHERE d.datname = current_database()) AS public_here,
         -- other reachable databases: any non-control one, or a control-named one that is not hardened
         (SELECT count(*) FROM pg_database d
           WHERE d.datallowconn AND d.datname <> current_database() AND has_database_privilege(current_user, d.oid, 'CONNECT')
             AND (d.datname !~ '${CONTROL_DB_PATTERN}' OR d.datacl IS NULL
                  OR EXISTS (SELECT 1 FROM aclexplode(d.datacl) a WHERE a.grantee = 0)
                  OR has_database_privilege(current_user, d.oid, 'TEMP') OR has_database_privilege(current_user, d.oid, 'CREATE')))::int AS other_dbs,
         (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'pg_catalog' AND p.proname = ANY ('{${REVOKED_BUILTINS.join(",")}}'::text[])
             AND has_function_privilege(current_user, p.oid, 'EXECUTE'))::int AS builtins,
         has_language_privilege(current_user, 'plpgsql', 'USAGE') AS plpgsql,
         -- every control object must be owned by one of the five owner roles; a --no-owner / -x restore (by a superuser
         -- or any other role) collapses the owner separation and is refused
         ((SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner
            WHERE n.nspname = 'control' AND r.rolname <> ALL (${OWNERS}))
          + (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner
              WHERE n.nspname = 'control' AND r.rolname <> ALL (${OWNERS})))::int AS superuser_owned`;

export type PrivilegeRow = { temp_here: boolean; create_here: boolean; public_here: boolean; other_dbs: number; builtins: number;
  plpgsql: boolean; superuser_owned: number };

export function privilegeProblems(r: PrivilegeRow | undefined): string[] {
  if (!r) return ["privilege check returned nothing"];
  const out: string[] = [];
  if (r.temp_here !== false) out.push("role has TEMP on the control database");
  if (r.create_here !== false) out.push("role has CREATE on the control database");
  if (r.public_here !== false) out.push("control database ACL grants CONNECT/TEMP to PUBLIC");
  if (r.other_dbs !== 0) out.push("role can CONNECT to a non-control or unhardened database");
  if (r.builtins !== 0) out.push("role can execute revoked built-in functions (advisory locks, large objects, NOTIFY, WAL or xid)");
  if (r.plpgsql !== false) out.push("role has USAGE on plpgsql");
  if (r.superuser_owned !== 0) out.push("control objects are owned by a superuser or another unexpected role (restored with --no-owner?)");
  return out;
}
