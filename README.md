# Trip Planner App

A Flask-based collaborative trip planner where authenticated users can:

- Create trips with destination and travel dates
- Invite other registered users to join a trip
- Store booking details by sector:
  - Stays
  - Flights
  - Attractions / specific tours
- See all their own accessible trips and bookings from a personal dashboard

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`.

## Notes

- Data is stored in a local SQLite file: `trip_planner.db`
- Invitations are email-based and require the invited user to already be registered.
