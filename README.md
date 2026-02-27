# Trip Planner App (Supabase URL/Key + Vercel Ready)

A collaborative trip planner where authenticated users can:

- Create and manage trips
- Invite other users to join each trip with invitation notifications
- Add bookings under sectors:
  - Stay bookings
  - Flight bookings
  - Attraction / activity bookings
- Store booking start/end dates and custom booking fields
- Access trip details only if they are participants

## Invitation flow

- If invited email is already registered:
  - the user gets an in-app notification and can accept or deny.
- If invited email is not registered:
  - invite is stored in `pending_invites`
  - after that user registers, invitation appears in their notifications.

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
  - Your project URL, e.g.:
    `https://ahutxsslectfarulmiyz.supabase.co`
- `SUPABASE_ANON_KEY`
  - Your anon key
- `SECRET_KEY`
  - Flask session secret

## Local run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# then edit .env values
export $(grep -v '^#' .env | xargs)
python run.py
```

Open `http://127.0.0.1:5000`.

## Supabase setup

1. Open Supabase SQL editor.
2. Run `supabase/schema.sql`.
3. If RLS is enabled, add policies to allow operations required by this app.

## Vercel deployment

This repo already includes:

- `api/index.py` (serverless entrypoint)
- `vercel.json` (routes all requests to Flask app)

Steps:

1. Import the repo into Vercel.
2. Add env vars: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SECRET_KEY`.
3. Deploy.
