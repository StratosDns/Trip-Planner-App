# Trip Planner App (Supabase + Vercel Ready)

A collaborative trip planner where authenticated users can:

- Create and manage trips
- Invite other users to join each trip
- Add bookings under sectors:
  - Stay bookings
  - Flight bookings
  - Attraction / activity bookings
- Access trip details only if they are participants

## Tech stack

- Flask app + Jinja templates
- Supabase Postgres as backend database
- Vercel Python runtime for deployment

## Environment variables

Set these locally and in Vercel project settings:

- `SUPABASE_DB_URL` (preferred) or `DATABASE_URL`
  - Postgres connection string from Supabase
  - Example format:
    `postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres`
- `SECRET_KEY`
  - Flask session secret

## Local run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SUPABASE_DB_URL="your_supabase_postgres_url"
export SECRET_KEY="replace-me"
python run.py
```

Open `http://127.0.0.1:5000`.

## Vercel deployment

This repo already includes:

- `api/index.py` (serverless entrypoint)
- `vercel.json` (routes all requests to Flask app)

Steps:

1. Import the repo into Vercel.
2. Add environment variables (`SUPABASE_DB_URL`, `SECRET_KEY`).
3. Deploy.

The app creates required database tables on startup if they do not exist.
