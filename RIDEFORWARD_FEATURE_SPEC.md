# RideForward Initiative — Portal & Communication Requirements

**Brand:** RideForward Initiative — Donation Platform / Website  
**Legal operator:** Global Connection (Pvt) Ltd

This document records the agreed applicant, donor, privacy, and notification requirements. These are requirements, not confirmation that the features are implemented.

## Applicant portal
- Applicants can register and manage a profile, personal story, CV, personal book, and application information.
- Applicants can submit supporting documents for admin review and see verification/application statuses.
- Applicants can browse donation listings and apply to specific donations.
- Applicants can view their own applications, membership, payments, and relevant notifications.
- Applicants receive email updates for important application, verification, selection, deadline, donation, and membership events.

## Donor portal
- Donors can register, create and manage their own donation listings, set/change deadlines, and review applicants to their own listings.
- Donors can review applicant-approved profile/story/CV content and relevant verification summaries.
- Donors can select applicants and update their selection. Selection is recorded as donor intent; RideForward admin retains allocation oversight.
- Donors receive email updates for new applications, applicant selection, deadline/listing changes, and relevant completion events.
- Donors must not access other donors' private listings/applicants, applicants' original identity/financial documents, admin investigation notes, or fundraising totals/progress.

## Applicant identity and contact-sharing rules
1. Before admin verification, donor-facing applicant identity is limited to the first name, displayed as no more than 8 characters, plus basic application information and status.
2. Before verification, hide surname/full name, email, phone, residential address, identity documents, financial records, and private supporting documents.
3. Admin verification does not by itself authorize disclosure of applicant contact details.
4. Once verified, an applicant may directly access/email the donor's email address for the specific donation they applied to.
5. When a donor selects an applicant, notify the applicant by email. The donor is expected to contact the selected applicant by phone.
6. Applicant phone number and other personal contact details remain hidden from the donor unless the applicant has consented and the applicable admin/contact-sharing permission is recorded.
7. Use secure portal links in notification emails; do not include sensitive documents or private records in email bodies.
8. Keep access scoped to the relevant donation and application; record contact-sharing and selection changes.

## Email notification events
- Account welcome/confirmation.
- Application submitted.
- Application status changed or additional information requested.
- Verification status changed.
- Donor receives a new application.
- Donor selection or selection change.
- Applicant receives selection notification.
- Donation deadline changed, extended, approaching, closed, paused, or reopened.
- Membership payment confirmation and expiry reminders.
- Donation completion, where recorded.

Notifications should be event-driven, recipient-scoped, deduplicated, and logged with delivery/failure status and retry handling. Users may control optional reminders; essential account/application notices should remain available.

## Countdown and deadline rules
- Each donation has one stored deadline shared by all visitors.
- Donors can set/change/extend deadlines through their own portal.
- Countdown is derived from the server-stored deadline, not visitor-local storage.
- Expired listings stop accepting new applications; existing applications remain viewable.
- Deadline changes are logged and reflected for applicants and donors.

## Security and implementation notes
- Keep applicant documents, verification notes, contact data, and donor-only records behind authenticated server-side authorization.
- Do not rely on hiding fields in static HTML or client-side JavaScript as access control.
- The existing static site and Google Apps Script/Sheets submission flow do not by themselves provide the full authenticated portals, granular access control, secure document storage, shared deadline engine, or reliable event-driven email system described above.
- Implement these features through a backend with authenticated roles, database-level access controls, secure document storage, transactional email, and audit logs. Never expose service credentials in browser code.
