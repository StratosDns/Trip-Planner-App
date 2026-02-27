from collections import defaultdict
from datetime import datetime
import os

from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash

from .auth import login_required
from .db import close_db, get_supabase, init_db

SECTORS = ["stay", "flight", "attraction"]
DATE_FORMAT = "%d/%m/%Y"


def _first(items):
    return items[0] if items else None


def parse_date_input(value):
    if not value:
        return None
    try:
        return datetime.strptime(value.strip(), DATE_FORMAT).date().isoformat()
    except ValueError:
        return None


def format_date_display(value):
    if not value:
        return "-"
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime(DATE_FORMAT)
    except ValueError:
        return value


def parse_custom_fields(raw_text):
    fields = {}
    if not raw_text:
        return fields

    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key:
            fields[key] = value
    return fields


def custom_fields_to_text(fields):
    if not fields:
        return ""
    return "\n".join(f"{k}: {v}" for k, v in fields.items())


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-change-me")

    init_db()
    app.teardown_appcontext(close_db)

    @app.context_processor
    def inject_notification_count():
        user_id = session.get("user_id")
        if not user_id:
            return {"pending_notification_count": 0}

        supabase = get_supabase()
        rows = (
            supabase.table("notifications")
            .select("id")
            .eq("user_id", user_id)
            .eq("status", "pending")
            .execute()
            .data
        )
        return {"pending_notification_count": len(rows)}

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
                supabase.table("users").select("id").eq("email", email).limit(1).execute().data
            )
            if existing:
                flash("User with this email already exists.", "danger")
                return redirect(url_for("register"))

            new_user = _first(
                supabase.table("users")
                .insert(
                    {
                        "name": name,
                        "email": email,
                        "password_hash": generate_password_hash(password),
                    }
                )
                .execute()
                .data
            )

            pending_invites = (
                supabase.table("pending_invites")
                .select("id,trip_id")
                .eq("email", email)
                .eq("status", "pending")
                .execute()
                .data
            )
            for invite in pending_invites:
                supabase.table("notifications").insert(
                    {
                        "user_id": new_user["id"],
                        "trip_id": invite["trip_id"],
                        "type": "trip_invite",
                        "message": "You were invited to join a trip.",
                        "status": "pending",
                    }
                ).execute()
                supabase.table("pending_invites").update({"status": "converted"}).eq(
                    "id", invite["id"]
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
                .select("id,trip_id,sector,title,provider,confirmation_code,start_date,end_date,custom_fields,created_at,trips(title)")
                .in_("trip_id", trip_ids)
                .order("created_at", desc=True)
                .execute()
                .data
            )

        for trip in trips:
            trip["start_date_display"] = format_date_display(trip.get("start_date"))
            trip["end_date_display"] = format_date_display(trip.get("end_date"))

        by_sector = defaultdict(list)
        for booking in bookings:
            trip_info = booking.get("trips") or {}
            booking["trip_title"] = trip_info.get("title", "Unknown trip")
            booking["start_date_display"] = format_date_display(booking.get("start_date"))
            booking["end_date_display"] = format_date_display(booking.get("end_date"))
            booking["custom_fields_text"] = custom_fields_to_text(booking.get("custom_fields") or {})
            by_sector[booking["sector"]].append(booking)

        notifications = (
            supabase.table("notifications")
            .select("id,trip_id,message,status,created_at,trips(title)")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .execute()
            .data
        )
        for notification in notifications:
            trip_info = notification.get("trips") or {}
            notification["trip_title"] = trip_info.get("title", "Trip")

        return render_template(
            "dashboard.html",
            trips=trips,
            by_sector=by_sector,
            sectors=SECTORS,
            notifications=notifications,
        )

    @app.route("/notifications/<int:notification_id>/<action>", methods=["POST"])
    @login_required
    def respond_notification(notification_id, action):
        if action not in {"accept", "deny"}:
            flash("Invalid action.", "danger")
            return redirect(url_for("dashboard"))

        user_id = session["user_id"]
        supabase = get_supabase()
        notification = _first(
            supabase.table("notifications")
            .select("id,trip_id,status")
            .eq("id", notification_id)
            .eq("user_id", user_id)
            .limit(1)
            .execute()
            .data
        )
        if not notification or notification["status"] != "pending":
            flash("Notification is no longer actionable.", "warning")
            return redirect(url_for("dashboard"))

        if action == "accept":
            supabase.table("trip_members").upsert(
                {
                    "trip_id": notification["trip_id"],
                    "user_id": user_id,
                    "role": "member",
                },
                on_conflict="trip_id,user_id",
            ).execute()

        supabase.table("notifications").update(
            {
                "status": "accepted" if action == "accept" else "denied",
                "responded_at": datetime.utcnow().isoformat(),
            }
        ).eq("id", notification_id).execute()

        flash(
            "Invitation accepted." if action == "accept" else "Invitation denied.",
            "success",
        )
        return redirect(url_for("dashboard"))

    @app.route("/trips/new", methods=["POST"])
    @login_required
    def create_trip():
        title = request.form.get("title", "").strip()
        destination = request.form.get("destination", "").strip()
        start_date = parse_date_input(request.form.get("start_date", "").strip())
        end_date = parse_date_input(request.form.get("end_date", "").strip())

        if not title or not destination:
            flash("Trip title and destination are required.", "danger")
            return redirect(url_for("dashboard"))
        if request.form.get("start_date", "").strip() and not start_date:
            flash("Use dd/mm/yyyy format for trip start date.", "danger")
            return redirect(url_for("dashboard"))
        if request.form.get("end_date", "").strip() and not end_date:
            flash("Use dd/mm/yyyy format for trip end date.", "danger")
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
        trip["start_date_display"] = format_date_display(trip.get("start_date"))
        trip["end_date_display"] = format_date_display(trip.get("end_date"))

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
            .select("id,sector,title,provider,confirmation_code,start_date,end_date,notes,custom_fields,created_at")
            .eq("trip_id", trip_id)
            .order("start_date")
            .execute()
            .data
        )
        for booking in bookings:
            booking["start_date_display"] = format_date_display(booking.get("start_date"))
            booking["end_date_display"] = format_date_display(booking.get("end_date"))
            booking["custom_fields_text"] = custom_fields_to_text(booking.get("custom_fields") or {})

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
        if user:
            supabase.table("notifications").insert(
                {
                    "user_id": user["id"],
                    "trip_id": trip_id,
                    "type": "trip_invite",
                    "message": "You have been invited to a trip. Accept or deny.",
                    "status": "pending",
                }
            ).execute()
            flash("Invitation sent as in-app notification.", "success")
        else:
            supabase.table("pending_invites").upsert(
                {
                    "trip_id": trip_id,
                    "email": email,
                    "invited_by": session["user_id"],
                    "status": "pending",
                },
                on_conflict="trip_id,email",
            ).execute()
            flash(
                "User is not registered yet. Save this invite and send an email from Supabase dashboard/automation to prompt signup.",
                "warning",
            )

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
        start_date_raw = request.form.get("start_date", "").strip()
        end_date_raw = request.form.get("end_date", "").strip()
        start_date = parse_date_input(start_date_raw)
        end_date = parse_date_input(end_date_raw)
        notes = request.form.get("notes", "").strip() or None
        custom_fields = parse_custom_fields(request.form.get("custom_fields", ""))

        if sector not in SECTORS or not title or not start_date:
            flash("Sector, title, and start date are required.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))
        if start_date_raw and not start_date:
            flash("Use dd/mm/yyyy format for booking start date.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))
        if end_date_raw and not end_date:
            flash("Use dd/mm/yyyy format for booking end date.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        supabase = get_supabase()
        supabase.table("bookings").insert(
            {
                "trip_id": trip_id,
                "sector": sector,
                "title": title,
                "provider": provider,
                "confirmation_code": confirmation_code,
                "start_date": start_date,
                "end_date": end_date,
                "notes": notes,
                "custom_fields": custom_fields,
                "created_by": session["user_id"],
            }
        ).execute()

        flash("Booking added.", "success")
        return redirect(url_for("trip_details", trip_id=trip_id))

    return app
