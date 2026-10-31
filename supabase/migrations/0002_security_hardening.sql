-- RideForward security hardening migration
-- Apply AFTER 0001_rideforward_core.sql on the new, empty RideForward project.
-- This improves account provisioning, column permissions, donor summaries,
-- donor selection workflow, and private document storage.
-- It is not a substitute for a full production security review and end-to-end tests.

-- 1) Provision applicant profiles on signup. Never trust user-supplied role metadata.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_first_name text;
begin
  v_first_name := nullif(trim(coalesce(new.raw_user_meta_data ->> 'first_name', '')), '');
  if v_first_name is null then
    v_first_name := 'Applicant';
  end if;

  insert into public.profiles (id, role, first_name, email)
  values (new.id, 'applicant', v_first_name, new.email)
  on conflict (id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created_rideforward on auth.users;
create trigger on_auth_user_created_rideforward
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- 2) Keep role, verification, email and admin-controlled fields out of
-- applicant self-service updates. RLS alone does not restrict individual columns.
revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
grant update (
  first_name,
  last_name,
  phone,
  district,
  occupation,
  story,
  cv_text,
  personal_book_text,
  profile_photo_path,
  updated_at
) on public.profiles to authenticated;

-- Reassert profile row policies. Applicants can only read/update themselves;
-- admins retain access through the existing admin policy.
drop policy if exists profiles_self_select on public.profiles;
drop policy if exists profiles_self_update on public.profiles;
drop policy if exists profiles_admin_all on public.profiles;

create policy profiles_self_select on public.profiles
  for select to authenticated
  using (id = (select auth.uid()) or public.is_admin());

create policy profiles_self_update on public.profiles
  for update to authenticated
  using (id = (select auth.uid()) and role = 'applicant')
  with check (id = (select auth.uid()) and role = 'applicant');

create policy profiles_admin_all on public.profiles
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- 3) Donors must not receive direct access to applicant profile rows or
-- private document metadata. Access the limited, listing-scoped view instead.
revoke all on public.applicant_documents from anon, authenticated;
grant select, insert on public.applicant_documents to authenticated;

drop policy if exists documents_applicant_read on public.applicant_documents;
drop policy if exists documents_applicant_insert on public.applicant_documents;
drop policy if exists documents_admin_all on public.applicant_documents;

create policy documents_applicant_read on public.applicant_documents
  for select to authenticated
  using (applicant_id = (select auth.uid()) or public.is_admin());

create policy documents_applicant_insert on public.applicant_documents
  for insert to authenticated
  with check (applicant_id = (select auth.uid()) and public.current_role() = 'applicant');

create policy documents_admin_all on public.applicant_documents
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- 4) Replace the initial donor view. It is deliberately owner-executed so
-- the view can read profile rows while still returning only approved fields.
-- The WHERE clause scopes every row to the authenticated donor's own listing.
drop view if exists public.donor_applicant_summary;
create view public.donor_applicant_summary
with (security_barrier = true)
as
select
  a.id as application_id,
  a.listing_id,
  left(p.first_name, 8) as applicant_display_name,
  case when p.verification_status = 'verified' then p.district else null end as district,
  case when p.verification_status = 'verified' then p.occupation else null end as occupation,
  case when p.verification_status = 'verified' then p.story else null end as story,
  case when p.verification_status = 'verified' then p.cv_text else null end as cv_text,
  a.status as application_status,
  p.verification_status,
  a.submitted_at,
  a.donor_selection,
  a.admin_allocation_approved
from public.applications a
join public.profiles p on p.id = a.applicant_id
join public.donation_listings l on l.id = a.listing_id
where l.donor_id = (select auth.uid())
  and public.current_role() = 'donor';

revoke all on public.donor_applicant_summary from anon;
grant select on public.donor_applicant_summary to authenticated;

-- 5) Donor selection is an intent only. Donors can change selection only for
-- applications attached to their own listings. Admin allocation remains separate.
create or replace function public.set_donor_selection(
  p_application_id uuid,
  p_selected boolean
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if not exists (
    select 1
    from public.applications a
    join public.donation_listings l on l.id = a.listing_id
    where a.id = p_application_id
      and l.donor_id = auth.uid()
      and exists (
        select 1 from public.profiles p
        where p.id = auth.uid() and p.role = 'donor'
      )
  ) then
    raise exception 'Application not found for this donor';
  end if;

  update public.applications
  set donor_selection = p_selected,
      updated_at = now()
  where id = p_application_id;
end;
$$;

revoke all on function public.set_donor_selection(uuid, boolean) from public, anon;
grant execute on function public.set_donor_selection(uuid, boolean) to authenticated;

-- 6) Create a private bucket. No public access is granted.
insert into storage.buckets (id, name, public)
values ('applicant-private-documents', 'applicant-private-documents', false)
on conflict (id) do update set public = false;

drop policy if exists "Applicants upload own private documents" on storage.objects;
create policy "Applicants upload own private documents"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'applicant-private-documents'
  and (storage.foldername(name))[1] = (select auth.uid())::text
  and public.current_role() = 'applicant'
);

drop policy if exists "Applicants read own private documents" on storage.objects;
create policy "Applicants read own private documents"
on storage.objects for select to authenticated
using (
  bucket_id = 'applicant-private-documents'
  and (
    (storage.foldername(name))[1] = (select auth.uid())::text
    or public.is_admin()
  )
);

drop policy if exists "Applicants update own private documents" on storage.objects;
create policy "Applicants update own private documents"
on storage.objects for update to authenticated
using (
  bucket_id = 'applicant-private-documents'
  and (storage.foldername(name))[1] = (select auth.uid())::text
  and public.current_role() = 'applicant'
)
with check (
  bucket_id = 'applicant-private-documents'
  and (storage.foldername(name))[1] = (select auth.uid())::text
  and public.current_role() = 'applicant'
);

drop policy if exists "Applicants delete own private documents" on storage.objects;
create policy "Applicants delete own private documents"
on storage.objects for delete to authenticated
using (
  bucket_id = 'applicant-private-documents'
  and (storage.foldername(name))[1] = (select auth.uid())::text
  and public.current_role() = 'applicant'
);

-- 7) Remove direct donor access to the full applications table. The donor
-- portal reads the summary view and uses the selection RPC above.
drop policy if exists applications_donor_read on public.applications;

-- 8) Keep the anon role out of all application and profile records.
revoke all on public.applications from anon;
revoke all on public.contact_sharing_permissions from anon;
revoke all on public.memberships from anon;
revoke all on public.notifications from anon;
revoke all on public.audit_events from anon;

-- NOTE: Admin provisioning must be performed by a trusted operator using a
-- secure server-side process or SQL Editor after verifying the account ID.
-- Never allow signup metadata or browser code to assign the admin role.

-- 9) Applicant-controlled sharing consent. Donors see story/CV only after
-- the applicant explicitly enables each field for donor review.
alter table public.profiles
  add column if not exists share_story_with_donors boolean not null default false,
  add column if not exists share_cv_with_donors boolean not null default false;

grant update (share_story_with_donors, share_cv_with_donors)
on public.profiles to authenticated;

create or replace view public.donor_applicant_summary
with (security_barrier = true)
as
select
  a.id as application_id,
  a.listing_id,
  left(p.first_name, 8) as applicant_display_name,
  case when p.verification_status = 'verified' then p.district else null end as district,
  case when p.verification_status = 'verified' then p.occupation else null end as occupation,
  case when p.verification_status = 'verified' and p.share_story_with_donors then p.story else null end as story,
  case when p.verification_status = 'verified' and p.share_cv_with_donors then p.cv_text else null end as cv_text,
  a.status as application_status,
  p.verification_status,
  a.submitted_at,
  a.donor_selection,
  a.admin_allocation_approved
from public.applications a
join public.profiles p on p.id = a.applicant_id
join public.donation_listings l on l.id = a.listing_id
where l.donor_id = (select auth.uid())
  and public.current_role() = 'donor';

-- 10) Applicants may create applications with only user-supplied fields.
-- They cannot set their own status/selection/admin approval or update any of
-- those workflow fields directly. Withdrawal is a narrowly scoped RPC.
revoke all on public.applications from anon, authenticated;
grant select on public.applications to authenticated;
grant insert (listing_id, applicant_id, applicant_message)
on public.applications to authenticated;

drop policy if exists applications_applicant_update on public.applications;

create or replace function public.withdraw_application(p_application_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  update public.applications
  set status = 'withdrawn',
      updated_at = now()
  where id = p_application_id
    and applicant_id = auth.uid()
    and status in ('submitted', 'under_review', 'needs_information', 'eligible');

  if not found then
    raise exception 'Application cannot be withdrawn';
  end if;
end;
$$;

revoke all on function public.withdraw_application(uuid) from public, anon;
grant execute on function public.withdraw_application(uuid) to authenticated;

-- Story/CV sharing switches are applicant-owned preferences, default OFF.
-- Role and verification fields remain server/admin controlled.
