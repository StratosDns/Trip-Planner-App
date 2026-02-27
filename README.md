# Trip Planner App (Supabase URL/Key + Vercel Ready)

A collaborative trip planner where authenticated users can:

- Create and manage trips
- Invite users with notification/email flow
- Add and edit bookings under sectors:
  - Stay bookings
  - Flight bookings
  - Attraction / activity bookings
- Store booking start/end dates and custom booking fields
- Access trip details only if they are participants

## Invitation flow

- If invited email is already registered:
  - the user gets an in-app notification and can accept or deny.
- If invited email is not registered:
  - app stores a `pending_invites` record,
  - app sends a signup email to that address,
  - after signup, invite is converted into in-app notification automatically.

## Booking edits

- Bookings can now be edited directly from trip details page.
- Editable fields: sector, title, provider, confirmation code, start/end date, notes, custom fields.

## Role management

- `owner`: all privileges, can invite with assigned role and change participant roles.
- `member`: can add/edit bookings.
- `observer`: read-only for trip details and bookings.
- any non-owner participant can leave the trip.

## Date format

The UI expects date input in `dd/mm/yyyy` format.
Dates are stored in Supabase as `date` values.

## Tech stack

- Flask app + Jinja templates
- Supabase (PostgREST via project URL + key)
- Vercel Python runtime for deployment

## Environment variables

Set these in Vercel Project Settings and local environment:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SECRET_KEY`
- `APP_BASE_URL` (used in email signup link)
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_FROM`

## Local run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
export $(grep -v '^#' .env | xargs)
python run.py
```

Open `http://127.0.0.1:5000`.

## Existing database? Run ALTER migration (recommended)

Because your tables already exist, run this migration script instead of re-running full create scripts:

- `supabase/migrations/0001_upgrade_existing_schema.sql`

This script alters existing tables to the latest app expectations (notifications/pending_invites, booking start/end/custom fields, backfill from legacy `booking_date`).

## Supabase setup

1. Open Supabase SQL editor.
2. For a fresh DB: run `supabase/schema.sql`.
3. For an existing DB, run migrations in order:
   - `supabase/migrations/0001_upgrade_existing_schema.sql`
   - `supabase/migrations/0002_trip_role_management.sql`
4. If RLS is enabled, add policies to allow operations required by this app.

## Vercel deployment

This repo already includes:

- `api/index.py` (serverless entrypoint)
- `vercel.json` (routes all requests to Flask app)

Steps:

1. Import the repo into Vercel.
2. Add env vars listed above.
3. Deploy.
