from collections import defaultdict
import os

from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash

from .auth import login_required
from .db import close_db, get_supabase, init_db

SECTORS = ["stay", "flight", "attraction"]


def _first(items):
    return items[0] if items else None


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-change-me")

    init_db()
    app.teardown_appcontext(close_db)

    @app.route("/")
    def landing():
        return render_template("landing.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            if not name or not email or not password:
                flash("All fields are required.", "danger")
                return redirect(url_for("register"))

            supabase = get_supabase()
            existing = (
                supabase.table("users")
                .select("id")
                .eq("email", email)
                .limit(1)
                .execute()
                .data
            )
            if existing:
                flash("User with this email already exists.", "danger")
                return redirect(url_for("register"))

            supabase.table("users").insert(
                {
                    "name": name,
                    "email": email,
                    "password_hash": generate_password_hash(password),
                }
            ).execute()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            supabase = get_supabase()
            users = (
                supabase.table("users")
                .select("id,name,password_hash")
                .eq("email", email)
                .limit(1)
                .execute()
                .data
            )
            user = _first(users)

            if user is None or not check_password_hash(user["password_hash"], password):
                flash("Invalid email or password.", "danger")
                return redirect(url_for("login"))

            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("landing"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user_id = session["user_id"]
        supabase = get_supabase()

        membership_rows = (
            supabase.table("trip_members").select("trip_id").eq("user_id", user_id).execute().data
        )
        trip_ids = [row["trip_id"] for row in membership_rows]

        trips = []
        bookings = []

        if trip_ids:
            trips = (
                supabase.table("trips")
                .select("id,title,destination,start_date,end_date,created_at")
                .in_("id", trip_ids)
                .order("start_date")
                .execute()
                .data
            )

            bookings = (
                supabase.table("bookings")
                .select("id,trip_id,sector,title,provider,confirmation_code,booking_date,notes,created_at,trips(title)")
                .in_("trip_id", trip_ids)
                .order("created_at", desc=True)
                .execute()
                .data
            )

        by_sector = defaultdict(list)
        for booking in bookings:
            trip_info = booking.get("trips") or {}
            booking["trip_title"] = trip_info.get("title", "Unknown trip")
            by_sector[booking["sector"]].append(booking)

        return render_template("dashboard.html", trips=trips, by_sector=by_sector, sectors=SECTORS)

    @app.route("/trips/new", methods=["POST"])
    @login_required
    def create_trip():
        title = request.form.get("title", "").strip()
        destination = request.form.get("destination", "").strip()
        start_date = request.form.get("start_date", "") or None
        end_date = request.form.get("end_date", "") or None

        if not title or not destination:
            flash("Trip title and destination are required.", "danger")
            return redirect(url_for("dashboard"))

        supabase = get_supabase()
        trip_rows = (
            supabase.table("trips")
            .insert(
                {
                    "title": title,
                    "destination": destination,
                    "start_date": start_date,
                    "end_date": end_date,
                    "created_by": session["user_id"],
                }
            )
            .execute()
            .data
        )
        trip = _first(trip_rows)
        if not trip:
            flash("Could not create trip.", "danger")
            return redirect(url_for("dashboard"))

        supabase.table("trip_members").upsert(
            {
                "trip_id": trip["id"],
                "user_id": session["user_id"],
                "role": "owner",
            },
            on_conflict="trip_id,user_id",
        ).execute()

        flash("Trip created.", "success")
        return redirect(url_for("trip_details", trip_id=trip["id"]))

    def ensure_member(trip_id, user_id):
        supabase = get_supabase()
        member = (
            supabase.table("trip_members")
            .select("trip_id")
            .eq("trip_id", trip_id)
            .eq("user_id", user_id)
            .limit(1)
            .execute()
            .data
        )
        return bool(member)

    @app.route("/trips/<int:trip_id>")
    @login_required
    def trip_details(trip_id):
        if not ensure_member(trip_id, session["user_id"]):
            flash("You do not have access to this trip.", "danger")
            return redirect(url_for("dashboard"))

        supabase = get_supabase()
        trip = _first(
            supabase.table("trips")
            .select("id,title,destination,start_date,end_date")
            .eq("id", trip_id)
            .limit(1)
            .execute()
            .data
        )

        member_rows = (
            supabase.table("trip_members")
            .select("role,users(name,email)")
            .eq("trip_id", trip_id)
            .order("role", desc=True)
            .execute()
            .data
        )
        members = [
            {
                "name": (row.get("users") or {}).get("name", "Unknown"),
                "email": (row.get("users") or {}).get("email", "-"),
                "role": row.get("role", "member"),
            }
            for row in member_rows
        ]

        bookings = (
            supabase.table("bookings")
            .select("id,sector,title,provider,confirmation_code,booking_date,notes,created_at")
            .eq("trip_id", trip_id)
            .order("booking_date")
            .execute()
            .data
        )

        return render_template("trip_details.html", trip=trip, members=members, bookings=bookings, sectors=SECTORS)

    @app.route("/trips/<int:trip_id>/invite", methods=["POST"])
    @login_required
    def invite_member(trip_id):
        if not ensure_member(trip_id, session["user_id"]):
            flash("You do not have access to invite users for this trip.", "danger")
            return redirect(url_for("dashboard"))

        email = request.form.get("email", "").strip().lower()
        supabase = get_supabase()

        user = _first(
            supabase.table("users").select("id").eq("email", email).limit(1).execute().data
        )
        if not user:
            flash("User not found. Ask them to register first.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        supabase.table("trip_members").upsert(
            {
                "trip_id": trip_id,
                "user_id": user["id"],
                "role": "member",
            },
            on_conflict="trip_id,user_id",
        ).execute()

        flash("Invitation processed.", "success")
        return redirect(url_for("trip_details", trip_id=trip_id))

    @app.route("/trips/<int:trip_id>/bookings", methods=["POST"])
    @login_required
    def add_booking(trip_id):
        if not ensure_member(trip_id, session["user_id"]):
            flash("You do not have access to this trip.", "danger")
            return redirect(url_for("dashboard"))

        sector = request.form.get("sector", "").strip().lower()
        title = request.form.get("title", "").strip()
        provider = request.form.get("provider", "").strip() or None
        confirmation_code = request.form.get("confirmation_code", "").strip() or None
        booking_date = request.form.get("booking_date", "").strip() or None
        notes = request.form.get("notes", "").strip() or None

        if sector not in SECTORS or not title:
            flash("Booking sector and title are required.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        supabase = get_supabase()
        supabase.table("bookings").insert(
            {
                "trip_id": trip_id,
                "sector": sector,
                "title": title,
                "provider": provider,
                "confirmation_code": confirmation_code,
                "booking_date": booking_date,
                "notes": notes,
                "created_by": session["user_id"],
            }
        ).execute()

        flash("Booking added.", "success")
        return redirect(url_for("trip_details", trip_id=trip_id))

    return app
