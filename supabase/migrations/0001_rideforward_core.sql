-- RideForward Initiative backend foundation (Supabase/Postgres)
-- Apply only to a new Supabase project after reviewing the README.
-- Do not run this against production without backups and a security review.

create extension if not exists pgcrypto;

create type public.account_role as enum ('applicant','donor','admin');
create type public.verification_state as enum ('pending','verified','needs_correction','rejected');
create type public.listing_state as enum ('draft','open','paused','closed','completed');
create type public.application_state as enum ('submitted','under_review','needs_information','eligible','selected','not_selected','withdrawn');
create type public.document_kind as enum ('identity','residence','income_employment','family_support','other');
create type public.document_state as enum ('pending','verified','needs_correction','rejected');
create type public.membership_state as enum ('pending','active','expired','cancelled');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role public.account_role not null default 'applicant',
  first_name text not null,
  last_name text,
  email text,
  phone text,
  district text,
  occupation text,
  story text,
  cv_text text,
  personal_book_text text,
  profile_photo_path text,
  verification_status public.verification_state not null default 'pending',
  donor_contact_email text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint profiles_first_name_nonempty check (length(trim(first_name)) > 0)
);

create table public.donation_listings (
  id uuid primary key default gen_random_uuid(),
  donor_id uuid not null references public.profiles(id) on delete restrict,
  title text not null,
  category text not null check (category in ('car','motorcycle','truck','suv','boat','housing','property','other')),
  description text not null,
  condition text,
  general_area text,
  requirements text,
  photos text[] not null default '{}',
  deadline timestamptz,
  status public.listing_state not null default 'draft',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  closed_at timestamptz,
  constraint listing_deadline_future check (deadline is null or deadline > created_at)
);

create table public.applications (
  id uuid primary key default gen_random_uuid(),
  listing_id uuid not null references public.donation_listings(id) on delete cascade,
  applicant_id uuid not null references public.profiles(id) on delete restrict,
  applicant_message text,
  status public.application_state not null default 'submitted',
  donor_selection boolean not null default false,
  admin_allocation_approved boolean not null default false,
  submitted_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (listing_id, applicant_id)
);

create table public.applicant_documents (
  id uuid primary key default gen_random_uuid(),
  applicant_id uuid not null references public.profiles(id) on delete cascade,
  kind public.document_kind not null,
  storage_path text not null unique,
  state public.document_state not null default 'pending',
  admin_note text,
  reviewed_by uuid references public.profiles(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);

create table public.contact_sharing_permissions (
  id uuid primary key default gen_random_uuid(),
  application_id uuid not null references public.applications(id) on delete cascade,
  applicant_id uuid not null references public.profiles(id) on delete cascade,
  donor_id uuid not null references public.profiles(id) on delete cascade,
  consented_at timestamptz not null,
  granted_by_admin uuid references public.profiles(id) on delete set null,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  unique(application_id)
);

create table public.memberships (
  id uuid primary key default gen_random_uuid(),
  applicant_id uuid not null references public.profiles(id) on delete cascade,
  plan_code text not null check (plan_code in ('1_month','3_month','6_month','12_month','lifetime')),
  amount_lkr numeric(12,2) not null check (amount_lkr >= 0),
  currency char(3) not null default 'LKR',
  status public.membership_state not null default 'pending',
  starts_at timestamptz,
  expires_at timestamptz,
  payment_provider text,
  provider_reference text,
  created_at timestamptz not null default now()
);

create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  recipient_id uuid not null references public.profiles(id) on delete cascade,
  event_key text not null,
  subject text not null,
  template_data jsonb not null default '{}',
  portal_path text,
  status text not null default 'queued' check (status in ('queued','sent','failed','skipped')),
  dedupe_key text not null unique,
  attempts integer not null default 0,
  last_error text,
  sent_at timestamptz,
  created_at timestamptz not null default now()
);

create table public.audit_events (
  id bigint generated always as identity primary key,
  actor_id uuid references public.profiles(id) on delete set null,
  action text not null,
  entity_type text not null,
  entity_id uuid,
  details jsonb not null default '{}',
  created_at timestamptz not null default now()
);

create index listings_status_deadline_idx on public.donation_listings(status, deadline);
create index applications_listing_status_idx on public.applications(listing_id, status);
create index applications_applicant_idx on public.applications(applicant_id, submitted_at desc);
create index documents_applicant_idx on public.applicant_documents(applicant_id, created_at desc);
create index notifications_recipient_idx on public.notifications(recipient_id, created_at desc);

-- Helper: current profile role. Security definer avoids recursive profile RLS checks.
create or replace function public.current_role()
returns public.account_role
language sql stable security definer
set search_path = public
as $$ select role from public.profiles where id = auth.uid() $$;

create or replace function public.is_admin()
returns boolean
language sql stable security definer
set search_path = public
as $$ select coalesce(public.current_role() = 'admin', false) $$;

-- All tables start private. Specific read/write policies are granted below.
alter table public.profiles enable row level security;
alter table public.donation_listings enable row level security;
alter table public.applications enable row level security;
alter table public.applicant_documents enable row level security;
alter table public.contact_sharing_permissions enable row level security;
alter table public.memberships enable row level security;
alter table public.notifications enable row level security;
alter table public.audit_events enable row level security;

-- Profile: applicant can see/edit own record; donors can see a limited applicant
-- projection through the secure listing/applicant view below; admins manage all.
create policy profiles_self_select on public.profiles for select
  using (id = auth.uid() or public.is_admin());
create policy profiles_self_update on public.profiles for update
  using (id = auth.uid() and role = public.current_role())
  with check (id = auth.uid() and role = public.current_role());
create policy profiles_admin_all on public.profiles for all
  using (public.is_admin()) with check (public.is_admin());

-- Listings: anyone authenticated can browse open listings; donor owns their rows;
-- admins oversee all.
create policy listings_open_read on public.donation_listings for select
  using (status = 'open' and (deadline is null or deadline > now()));
create policy listings_owner_manage on public.donation_listings for all
  using (donor_id = auth.uid() and public.current_role() = 'donor')
  with check (donor_id = auth.uid() and public.current_role() = 'donor');
create policy listings_admin_all on public.donation_listings for all
  using (public.is_admin()) with check (public.is_admin());

-- Applications: applicant sees own; listing donor sees applications to own listings;
-- admin sees all. Donor cannot see private document rows via this policy.
create policy applications_applicant_read on public.applications for select
  using (applicant_id = auth.uid());
create policy applications_applicant_insert on public.applications for insert
  with check (
    applicant_id = auth.uid()
    and public.current_role() = 'applicant'
    and exists (select 1 from public.donation_listings l
      where l.id = listing_id and l.status = 'open'
      and (l.deadline is null or l.deadline > now()))
  );
create policy applications_applicant_update on public.applications for update
  using (applicant_id = auth.uid() and status in ('submitted','needs_information'))
  with check (applicant_id = auth.uid());
create policy applications_donor_read on public.applications for select
  using (exists (select 1 from public.donation_listings l
    where l.id = listing_id and l.donor_id = auth.uid()));
create policy applications_admin_all on public.applications for all
  using (public.is_admin()) with check (public.is_admin());

-- Documents and contact permissions are applicant/admin only. Donors are denied.
create policy documents_applicant_read on public.applicant_documents for select
  using (applicant_id = auth.uid());
create policy documents_applicant_insert on public.applicant_documents for insert
  with check (applicant_id = auth.uid() and public.current_role() = 'applicant');
create policy documents_admin_all on public.applicant_documents for all
  using (public.is_admin()) with check (public.is_admin());

create policy contact_permission_applicant_read on public.contact_sharing_permissions for select
  using (applicant_id = auth.uid());
create policy contact_permission_admin_all on public.contact_sharing_permissions for all
  using (public.is_admin()) with check (public.is_admin());

create policy memberships_applicant_read on public.memberships for select
  using (applicant_id = auth.uid());
create policy memberships_admin_all on public.memberships for all
  using (public.is_admin()) with check (public.is_admin());

create policy notifications_recipient_read on public.notifications for select
  using (recipient_id = auth.uid());
create policy notifications_admin_all on public.notifications for all
  using (public.is_admin()) with check (public.is_admin());

create policy audit_admin_read on public.audit_events for select
  using (public.is_admin());
create policy audit_admin_insert on public.audit_events for insert
  with check (public.is_admin());

-- Donor-facing applicant summary: truncate first name to 8 chars and expose no
-- contact, address, or private documents. Admin must approve allocation separately.
create or replace view public.donor_applicant_summary
with (security_invoker = true)
as
select
  a.id as application_id,
  a.listing_id,
  left(p.first_name, 8) as applicant_display_name,
  p.district,
  p.occupation,
  p.story,
  p.cv_text,
  a.status as application_status,
  p.verification_status,
  a.submitted_at,
  a.donor_selection,
  a.admin_allocation_approved
from public.applications a
join public.profiles p on p.id = a.applicant_id
join public.donation_listings l on l.id = a.listing_id
where l.donor_id = auth.uid()
  and public.current_role() = 'donor'
  and p.verification_status = 'verified';

grant select on public.donor_applicant_summary to authenticated;

-- Storage setup note:
-- Create a PRIVATE bucket named 'applicant-private-documents' in Supabase.
-- Storage object policies must verify the path's first folder is auth.uid()
-- and allow admin access only. Do not make this bucket public.
-- Email sending/payment provider callbacks must run server-side (Edge Functions).
