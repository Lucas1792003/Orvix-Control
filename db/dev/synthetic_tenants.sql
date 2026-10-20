-- DEV SEED ONLY: synthetic tenants for the lifecycle model and dashboard. All names are invented
-- (".invalid"/"example" style), is_synthetic is enforced by a CHECK constraint.
INSERT INTO control.tenants (slug, display_name, status, shop_count, user_count, admin_mfa_verified, status_changed_at, created_at) VALUES
  ('syn-golden-lotus',  'Synthetic Golden Lotus Mart',  'active',             2, 9, true,  now() - interval '40 days', now() - interval '90 days'),
  ('syn-river-bazaar',  'Synthetic River Bazaar',       'active',             1, 4, true,  now() - interval '12 days', now() - interval '60 days'),
  ('syn-teak-house',    'Synthetic Teak House Grocers', 'past_due',           3, 14, true, now() - interval '3 days',  now() - interval '200 days'),
  ('syn-jade-corner',   'Synthetic Jade Corner Shop',   'suspended',          1, 3, false, now() - interval '5 days',  now() - interval '120 days'),
  ('syn-monsoon-mini',  'Synthetic Monsoon Mini',       'provisioning',       0, 0, false, now() - interval '30 hours', now() - interval '2 days'),
  ('syn-pagoda-pharm',  'Synthetic Pagoda Pharmacy',    'draft',              0, 0, false, now() - interval '2 hours',  now() - interval '2 hours'),
  ('syn-ruby-tea',      'Synthetic Ruby Tea Stall',     'locked',             1, 2, true,  now() - interval '1 day',   now() - interval '75 days'),
  ('syn-old-market',    'Synthetic Old Market Co',      'archived',           0, 0, false, now() - interval '90 days', now() - interval '400 days')
ON CONFLICT DO NOTHING;
