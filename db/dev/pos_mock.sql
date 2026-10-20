-- DEV FIXTURE ONLY (not a control migration, not in the ledger).
-- A synthetic stand-in for POS tenant tables, so tests can prove that no control role can read tenant data.
-- Every value is invented. Nothing here is copied from, or connected to, the ShwePhaLa POS.
CREATE SCHEMA IF NOT EXISTS pos_mock;
REVOKE ALL ON SCHEMA pos_mock FROM PUBLIC;
CREATE TABLE IF NOT EXISTS pos_mock.organizations (id text PRIMARY KEY, name text NOT NULL, is_active boolean NOT NULL DEFAULT true);
CREATE TABLE IF NOT EXISTS pos_mock.sales (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, org_id text NOT NULL REFERENCES pos_mock.organizations(id), total_minor bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS pos_mock.users (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, org_id text NOT NULL REFERENCES pos_mock.organizations(id), email text NOT NULL, role text NOT NULL);
REVOKE ALL ON ALL TABLES IN SCHEMA pos_mock FROM PUBLIC;
INSERT INTO pos_mock.organizations VALUES ('org-synthetic-a', 'Synthetic Org A'), ('org-synthetic-b', 'Synthetic Org B') ON CONFLICT DO NOTHING;
INSERT INTO pos_mock.sales (org_id, total_minor) SELECT 'org-synthetic-a', 12345 WHERE NOT EXISTS (SELECT 1 FROM pos_mock.sales);
INSERT INTO pos_mock.users (org_id, email, role) SELECT 'org-synthetic-a', 'admin@example.invalid', 'ADMIN' WHERE NOT EXISTS (SELECT 1 FROM pos_mock.users);
