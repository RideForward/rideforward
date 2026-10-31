# RideForward Initiative backend starter

This repository now contains a **Supabase/Postgres backend foundation**, not a live hosted backend.

## Stack
- Supabase Auth for account identity
- PostgreSQL for profiles, donation listings, applications, document metadata, contact-sharing permissions, memberships, notifications and audit events
- Private Supabase Storage bucket for applicant documents
- Supabase Edge Functions (to be added/configured) for email, deadline jobs, payment callbacks and admin workflows

## Current status
- `supabase/migrations/0001_rideforward_core.sql`: core schema, enums, indexes, RLS policies and a donor-facing applicant summary view.
- The website itself still uses its existing static form / Google Apps Script pilot flow. It is not yet wired to this schema.
- No Supabase project has been provisioned, no migration has been applied, and no secrets/provider credentials are stored in this repository.

## Setup (project owner)
1. Create a Supabase project in the intended organization and choose the correct region/data-retention configuration.
2. Review `supabase/migrations/0001_rideforward_core.sql` with a database/security engineer before applying.
3. Apply it to a **new empty project** using Supabase CLI or SQL Editor. Do not run against existing production data without backup and migration review.
4. Create a private Storage bucket named `applicant-private-documents`. Add bucket/object policies that only allow an applicant to access objects under their own `auth.uid()` folder and admins to review. Never use a public bucket for identity/financial documents.
5. Configure authentication email confirmation, password reset, MFA for admin accounts, and approved redirect URLs.
6. Add server-side Edge Functions for profile onboarding/role assignment, application submission, document review, donor applicant summaries, selection/allocation approval, notification dispatch, deadline processing and payment webhooks.
7. Store provider secrets only in Supabase project secrets; never in HTML, client JavaScript, GitHub, or a public environment file.
8. Test with separate applicant, donor and admin accounts, including attempts to access another user's records and private documents.
9. Only after tests pass, connect the frontend to Supabase using the public anon key and authenticated sessions. Never expose the service-role key.

## Critical authorization notes
- Account roles must be assigned/changed only by trusted server/admin code. Do not let users promote themselves to donor/admin.
- Review the RLS policies and view semantics carefully. A donor must only see applications for their own listing; applicant PII and documents remain restricted.
- Donor selection is a recorded intention. RideForward admin allocation approval is a separate step.
- Verification alone does not reveal applicant phone/email. Contact sharing requires explicit consent plus an admin permission record.
- Email bodies should contain only safe summaries and secure portal links. Notification delivery and retries belong in a server-side queue.
- Deadline/countdown is authoritative from database timestamps; do not use visitor localStorage.
- This is a starter migration and requires a production security review. In particular, implement strict server-side role management, storage policies, audit triggers, and transactional notification/payment functions before launch.

## Brand
RideForward Initiative  
Operated by Global Connection (Pvt) Ltd
