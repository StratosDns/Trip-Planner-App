# Trip Planner App (Supabase URL/Key + Vercel Ready)

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
- Supabase (PostgREST via project URL + key)
- Vercel Python runtime for deployment

## Do I need a file with Supabase credentials?

You **do not** need to commit a credentials file.
Use environment variables in Vercel and locally.

For convenience, this repo includes `.env.example` with the expected keys.
Create your own local `.env` from it, but never commit real secrets.

## Environment variables

Set these in Vercel Project Settings and local environment:

- `SUPABASE_URL`
  - Your project URL, e.g.:
    `https://ahutxsslectfarulmiyz.supabase.co`
- `SUPABASE_ANON_KEY`
  - Your anon key (public key used by the app client)
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

## Vercel deployment

This repo already includes:

- `api/index.py` (serverless entrypoint)
- `vercel.json` (routes all requests to Flask app)

Steps:

1. Import the repo into Vercel.
2. Add env vars: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SECRET_KEY`.
3. Deploy.

## Important Supabase note

This app now uses Supabase REST API through the project URL + key.
So your tables (`users`, `trips`, `trip_members`, `bookings`) must exist in Supabase.
If Row Level Security is enabled, add policies that allow the operations your app performs.
