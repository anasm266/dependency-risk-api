create table if not exists schema_migrations (
  id text primary key,
  applied_at timestamptz not null default now()
);

create table if not exists users (
  id uuid primary key,
  github_id text not null unique,
  login text not null,
  avatar_url text,
  created_at timestamptz not null default now()
);

create table if not exists sessions (
  id text primary key,
  user_id uuid not null references users(id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists sessions_user_id_idx on sessions(user_id);
create index if not exists sessions_expires_at_idx on sessions(expires_at);

create table if not exists github_installations (
  id text primary key,
  account_login text not null,
  account_type text not null,
  suspended_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists repos (
  id uuid primary key,
  provider text not null default 'github',
  full_name text not null unique,
  default_branch text not null default 'main',
  private boolean not null default false,
  installation_id text references github_installations(id) on delete set null,
  latest_scan_id uuid,
  latest_scan_status text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists repos_installation_id_idx on repos(installation_id);

create table if not exists repo_memberships (
  user_id uuid not null references users(id) on delete cascade,
  repo_id uuid not null references repos(id) on delete cascade,
  role text not null default 'admin',
  created_at timestamptz not null default now(),
  primary key (user_id, repo_id)
);

create table if not exists policies (
  repo_id uuid primary key references repos(id) on delete cascade,
  block_lifecycle_scripts boolean not null default true,
  block_secret_reads boolean not null default true,
  allowed_network_hosts text[] not null default array['registry.npmjs.org'],
  max_blast_radius integer not null default 40,
  require_approval_for_new_risky_packages boolean not null default true,
  updated_at timestamptz not null default now()
);

create table if not exists scans (
  id uuid primary key,
  repo_id uuid not null references repos(id) on delete cascade,
  status text not null,
  source text not null,
  commit_sha text,
  pull_request_number integer,
  started_at timestamptz,
  finished_at timestamptz,
  error text,
  created_at timestamptz not null default now()
);

create index if not exists scans_repo_id_created_at_idx on scans(repo_id, created_at desc);
create index if not exists scans_status_idx on scans(status);

create table if not exists scan_packages (
  id uuid primary key,
  scan_id uuid not null references scans(id) on delete cascade,
  package_name text not null,
  package_version text,
  lifecycle_scripts jsonb not null default '{}'::jsonb,
  blast_radius integer not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists dependency_edges (
  id uuid primary key,
  scan_id uuid not null references scans(id) on delete cascade,
  from_package text not null,
  to_package text not null,
  created_at timestamptz not null default now()
);

create table if not exists findings (
  id uuid primary key,
  scan_id uuid not null references scans(id) on delete cascade,
  severity text not null,
  rule_id text not null,
  package_name text not null,
  package_version text,
  title text not null,
  evidence jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists findings_scan_id_idx on findings(scan_id);
create index if not exists findings_severity_idx on findings(severity);

create table if not exists jobs (
  id uuid primary key,
  type text not null,
  status text not null,
  payload jsonb not null default '{}'::jsonb,
  attempts integer not null default 0,
  max_attempts integer not null default 5,
  run_at timestamptz not null default now(),
  locked_at timestamptz,
  locked_by text,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists jobs_queue_idx on jobs(status, run_at, created_at);
create index if not exists jobs_type_idx on jobs(type);

create table if not exists outbox_events (
  id uuid primary key,
  event_type text not null,
  payload jsonb not null,
  status text not null default 'queued',
  attempts integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists outbox_events_queue_idx on outbox_events(status, created_at);

create table if not exists webhook_endpoints (
  id uuid primary key,
  user_id uuid not null references users(id) on delete cascade,
  url text not null,
  secret text not null,
  active boolean not null default true,
  description text,
  created_at timestamptz not null default now()
);

create table if not exists webhook_deliveries (
  id uuid primary key,
  endpoint_id uuid not null references webhook_endpoints(id) on delete cascade,
  outbox_event_id uuid not null references outbox_events(id) on delete cascade,
  event_type text not null,
  status text not null,
  attempt integer not null default 0,
  status_code integer,
  latency_ms integer,
  response_excerpt text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists webhook_deliveries_endpoint_idx on webhook_deliveries(endpoint_id, created_at desc);

create table if not exists audit_logs (
  id uuid primary key,
  actor_user_id uuid references users(id) on delete set null,
  repo_id uuid references repos(id) on delete set null,
  action text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists audit_logs_created_at_idx on audit_logs(created_at desc);
create index if not exists audit_logs_repo_id_idx on audit_logs(repo_id);

create table if not exists idempotency_keys (
  scope text not null,
  key text not null,
  response jsonb not null,
  created_at timestamptz not null default now(),
  primary key (scope, key)
);
