from collections import defaultdict
from datetime import datetime
from email.message import EmailMessage
import logging
import os
import re
import smtplib

from flask import Flask, render_template, request, redirect, url_for, flash, session
from markupsafe import Markup, escape
from werkzeug.security import check_password_hash, generate_password_hash

from .auth import login_required
from .db import close_db, get_supabase, init_db

SECTORS = ["stay", "flight", "attraction"]
ASSIGNABLE_ROLES = ["member", "observer"]
VISIBILITY_LEVELS = ["private", "friends", "public"]
TRIP_VISIBILITIES = ["private", "public"]
DATE_FORMAT = "%d/%m/%Y"

logger = logging.getLogger(__name__)


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
        if key.strip():
            fields[key.strip()] = value.strip()
    return fields


def custom_fields_to_text(fields):
    if not fields:
        return ""
    if isinstance(fields, str):
        return fields
    if not isinstance(fields, dict):
        return str(fields)
    return "\n".join(f"{k}: {v}" for k, v in fields.items())


def relation_to_object(value):
    if isinstance(value, list):
        return value[0] if value else {}
    if isinstance(value, dict):
        return value
    return {}


def mask_links_text(value):
    if value is None:
        return "-"
    return re.sub(r"https?://\S+", "Link", str(value))


def linkify_compact(value):
    if value is None:
        return Markup('-')
    text = str(value)
    url_pattern = re.compile(r"https?://\S+")

    def _repl(match):
        url = match.group(0)
        safe_url = escape(url)
        return f'<a href="{safe_url}" target="_blank" rel="noopener noreferrer">Link</a>'

    escaped = escape(text)
    linked = url_pattern.sub(lambda m: _repl(m), str(escaped))
    return Markup(linked)




def can_view_value(level, is_friend=False, is_self=False):
    if is_self:
        return True
    if level == "public":
        return True
    if level == "friends" and is_friend:
        return True
    return False


def send_signup_invite_email(invited_email, inviter_name, trip_title):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port_raw = os.getenv("SMTP_PORT", "587")
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM") or smtp_user
    app_base_url = os.getenv("APP_BASE_URL", "")

    if not (smtp_host and smtp_user and smtp_password and smtp_from):
        logger.warning("SMTP not fully configured; skipping invite email send")
        return False

    try:
        smtp_port = int(smtp_port_raw)
    except ValueError:
        logger.exception("SMTP_PORT is invalid: %s", smtp_port_raw)
        return False

    register_url = f"{app_base_url.rstrip('/')}/register?email={invited_email}" if app_base_url else "/register"

    msg = EmailMessage()
    msg["Subject"] = f"You're invited to join trip: {trip_title}"
    msg["From"] = smtp_from
    msg["To"] = invited_email
    msg.set_content(
        f"Hi,\n\n{inviter_name} invited you to join the trip '{trip_title}' on Trip Planner.\n"
        f"Create your account here: {register_url}\n\n"
        "After signup, your invitation will appear in your notifications."
    )

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        return True
    except Exception:
        logger.exception("Failed to send signup invite email to %s", invited_email)
        return False


def fetch_bookings_for_trip_ids(supabase, trip_ids):
    if not trip_ids:
        return []
    try:
        return (
            supabase.table("bookings")
            .select("id,trip_id,sector,title,provider,confirmation_code,start_date,end_date,notes,custom_fields,created_at,trips(title)")
            .in_("trip_id", trip_ids)
            .order("created_at", desc=True)
            .execute()
            .data
        )
    except Exception:
        legacy = (
            supabase.table("bookings")
            .select("id,trip_id,sector,title,provider,confirmation_code,booking_date,notes,created_at,trips(title)")
            .in_("trip_id", trip_ids)
            .order("created_at", desc=True)
            .execute()
            .data
        )
        for item in legacy:
            item["start_date"] = item.get("booking_date")
            item["end_date"] = None
            item["custom_fields"] = {}
        return legacy


def fetch_trip_bookings(supabase, trip_id):
    try:
        return (
            supabase.table("bookings")
            .select("id,sector,title,provider,confirmation_code,start_date,end_date,notes,custom_fields,created_at")
            .eq("trip_id", trip_id)
            .order("start_date")
            .execute()
            .data
        )
    except Exception:
        legacy = (
            supabase.table("bookings")
            .select("id,sector,title,provider,confirmation_code,booking_date,notes,created_at")
            .eq("trip_id", trip_id)
            .order("booking_date")
            .execute()
            .data
        )
        for item in legacy:
            item["start_date"] = item.get("booking_date")
            item["end_date"] = None
            item["custom_fields"] = {}
        return legacy


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-change-me")

    init_db()
    app.teardown_appcontext(close_db)

    @app.template_filter("linkify_compact")
    def _linkify_compact_filter(value):
        return linkify_compact(value)

    @app.template_filter("mask_links")
    def _mask_links_filter(value):
        return mask_links_text(value)

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

    def get_trip_role(trip_id, user_id):
        supabase = get_supabase()
        row = _first(
            supabase.table("trip_members")
            .select("role")
            .eq("trip_id", trip_id)
            .eq("user_id", user_id)
            .limit(1)
            .execute()
            .data
        )
        return (row or {}).get("role")

    def ensure_member(trip_id, user_id):
        return get_trip_role(trip_id, user_id) is not None

    def get_friend_ids(user_id):
        supabase = get_supabase()
        rows = supabase.table("friendships").select("friend_id").eq("user_id", user_id).execute().data
        return {row["friend_id"] for row in rows}

    def ensure_profile(user_id):
        supabase = get_supabase()
        existing = supabase.table("profiles").select("user_id").eq("user_id", user_id).limit(1).execute().data
        if not existing:
            supabase.table("profiles").insert({"user_id": user_id}).execute()


    @app.route("/")
    def landing():
        if session.get("user_id"):
            return redirect(url_for("feed"))
        return render_template("landing.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        prefill_email = request.args.get("email", "").strip().lower()
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if not name or not email or not password:
                flash("All fields are required.", "danger")
                return redirect(url_for("register", email=email))

            supabase = get_supabase()
            existing = supabase.table("users").select("id").eq("email", email).limit(1).execute().data
            if existing:
                flash("User with this email already exists.", "danger")
                return redirect(url_for("register", email=email))

            new_user = _first(
                supabase.table("users")
                .insert({"name": name, "email": email, "password_hash": generate_password_hash(password)})
                .execute()
                .data
            )

            pending_invites = (
                supabase.table("pending_invites")
                .select("id,trip_id,invite_role")
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
                        "invite_role": invite.get("invite_role", "member"),
                    }
                ).execute()
                supabase.table("pending_invites").update({"status": "converted"}).eq("id", invite["id"]).execute()

            ensure_profile(new_user["id"])
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html", prefill_email=prefill_email)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            supabase = get_supabase()
            user = _first(
                supabase.table("users").select("id,name,password_hash").eq("email", email).limit(1).execute().data
            )
            if user is None or not check_password_hash(user["password_hash"], password):
                flash("Invalid email or password.", "danger")
                return redirect(url_for("login"))
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            ensure_profile(user["id"])
            flash(f"Welcome back, {user['name']}!", "success")
            return redirect(url_for("feed"))
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("landing"))


    @app.route("/feed")
    @login_required
    def feed():
        user_id = session["user_id"]
        supabase = get_supabase()
        friend_ids = get_friend_ids(user_id)

        public_trips = (
            supabase.table("trips")
            .select("id,title,destination,start_date,end_date,visibility,created_by,users(name)")
            .eq("visibility", "public")
            .order("created_at", desc=True)
            .execute()
            .data
        )

        member_rows = supabase.table("trip_members").select("trip_id").eq("user_id", user_id).execute().data
        member_trip_ids = {r["trip_id"] for r in member_rows}

        pending_join_rows = (
            supabase.table("join_requests")
            .select("trip_id")
            .eq("requester_id", user_id)
            .eq("status", "pending")
            .execute()
            .data
        )
        pending_join_ids = {r["trip_id"] for r in pending_join_rows}

        def trip_priority(t):
            is_friend_trip = t.get("created_by") in friend_ids
            return (0 if is_friend_trip else 1, )

        normalized = []
        for trip in public_trips:
            creator = relation_to_object(trip.get("users"))
            trip["creator_name"] = creator.get("name", "Unknown")
            trip["start_date_display"] = format_date_display(trip.get("start_date"))
            trip["end_date_display"] = format_date_display(trip.get("end_date"))
            trip["visibility"] = trip.get("visibility", "private")
            trip["is_friend_trip"] = trip.get("created_by") in friend_ids
            trip["is_member"] = trip["id"] in member_trip_ids
            trip["join_pending"] = trip["id"] in pending_join_ids
            normalized.append(trip)

        normalized.sort(key=trip_priority)
        return render_template("feed.html", trips=normalized)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user_id = session["user_id"]
        supabase = get_supabase()
        membership_rows = supabase.table("trip_members").select("trip_id").eq("user_id", user_id).execute().data
        trip_ids = [row["trip_id"] for row in membership_rows]

        trips = []
        bookings = []
        if trip_ids:
            trips = (
                supabase.table("trips")
                .select("id,title,destination,start_date,end_date,visibility,created_at")
                .in_("id", trip_ids)
                .order("start_date")
                .execute()
                .data
            )
            bookings = fetch_bookings_for_trip_ids(supabase, trip_ids)

        for trip in trips:
            trip["start_date_display"] = format_date_display(trip.get("start_date"))
            trip["end_date_display"] = format_date_display(trip.get("end_date"))
            trip["visibility"] = trip.get("visibility", "private")

        by_sector = defaultdict(list)
        for booking in bookings:
            trip_info = relation_to_object(booking.get("trips"))
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
            trip_info = relation_to_object(notification.get("trips"))
            notification["trip_title"] = trip_info.get("title", "Trip")

        return render_template("dashboard.html", trips=trips, by_sector=by_sector, sectors=SECTORS, notifications=notifications)

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
            .select("id,trip_id,status,invite_role,type,friend_request_id,join_request_id")
            .eq("id", notification_id)
            .eq("user_id", user_id)
            .limit(1)
            .execute()
            .data
        )
        if not notification or notification["status"] != "pending":
            flash("Notification is no longer actionable.", "warning")
            return redirect(url_for("dashboard"))

        ntype = notification.get("type")
        if ntype == "trip_invite":
            if action == "accept":
                supabase.table("trip_members").upsert(
                    {"trip_id": notification["trip_id"], "user_id": user_id, "role": notification.get("invite_role") or "member"},
                    on_conflict="trip_id,user_id",
                ).execute()
        elif ntype == "friend_request":
            req_id = notification.get("friend_request_id")
            req = _first(supabase.table("friend_requests").select("requester_id,addressee_id,status").eq("id", req_id).limit(1).execute().data)
            if req and req.get("status") == "pending":
                supabase.table("friend_requests").update(
                    {"status": "accepted" if action == "accept" else "rejected", "responded_at": datetime.utcnow().isoformat()}
                ).eq("id", req_id).execute()
                if action == "accept":
                    supabase.table("friendships").upsert(
                        [{"user_id": req["requester_id"], "friend_id": req["addressee_id"]}, {"user_id": req["addressee_id"], "friend_id": req["requester_id"]}],
                        on_conflict="user_id,friend_id",
                    ).execute()
        elif ntype == "join_request":
            join_id = notification.get("join_request_id")
            jreq = _first(supabase.table("join_requests").select("trip_id,requester_id,status").eq("id", join_id).limit(1).execute().data)
            if jreq and jreq.get("status") == "pending":
                supabase.table("join_requests").update(
                    {"status": "approved" if action == "accept" else "rejected", "responded_at": datetime.utcnow().isoformat()}
                ).eq("id", join_id).execute()
                if action == "accept":
                    supabase.table("trip_members").upsert(
                        {"trip_id": jreq["trip_id"], "user_id": jreq["requester_id"], "role": "observer"},
                        on_conflict="trip_id,user_id",
                    ).execute()
        
        supabase.table("notifications").update(
            {"status": "accepted" if action == "accept" else "denied", "responded_at": datetime.utcnow().isoformat()}
        ).eq("id", notification_id).execute()

        flash("Request accepted." if action == "accept" else "Request denied.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/trips/new", methods=["POST"])
    @login_required
    def create_trip():
        title = request.form.get("title", "").strip()
        destination = request.form.get("destination", "").strip()
        start_date_raw = request.form.get("start_date", "").strip()
        end_date_raw = request.form.get("end_date", "").strip()
        visibility = request.form.get("visibility", "private").strip().lower()
        start_date = parse_date_input(start_date_raw)
        end_date = parse_date_input(end_date_raw)

        if not title or not destination:
            flash("Trip title and destination are required.", "danger")
            return redirect(url_for("dashboard"))
        if start_date_raw and not start_date:
            flash("Use dd/mm/yyyy format for trip start date.", "danger")
            return redirect(url_for("dashboard"))
        if end_date_raw and not end_date:
            flash("Use dd/mm/yyyy format for trip end date.", "danger")
            return redirect(url_for("dashboard"))
        if visibility not in TRIP_VISIBILITIES:
            flash("Invalid trip visibility.", "danger")
            return redirect(url_for("dashboard"))

        supabase = get_supabase()
        trip = _first(
            supabase.table("trips")
            .insert({"title": title, "destination": destination, "start_date": start_date, "end_date": end_date, "visibility": visibility, "created_by": session["user_id"]})
            .execute()
            .data
        )
        if not trip:
            flash("Could not create trip.", "danger")
            return redirect(url_for("dashboard"))

        supabase.table("trip_members").upsert(
            {"trip_id": trip["id"], "user_id": session["user_id"], "role": "owner"},
            on_conflict="trip_id,user_id",
        ).execute()

        flash("Trip created.", "success")
        return redirect(url_for("trip_details", trip_id=trip["id"]))

    @app.route("/trips/<int:trip_id>")
    @login_required
    def trip_details(trip_id):
        role = get_trip_role(trip_id, session["user_id"])
        if role is None:
            flash("You do not have access to this trip.", "danger")
            return redirect(url_for("dashboard"))

        supabase = get_supabase()
        trip = _first(
            supabase.table("trips")
            .select("id,title,destination,start_date,end_date,visibility")
            .eq("id", trip_id)
            .limit(1)
            .execute()
            .data
        )
        if not trip:
            flash("Trip not found.", "danger")
            return redirect(url_for("dashboard"))
        trip["start_date_display"] = format_date_display(trip.get("start_date"))
        trip["end_date_display"] = format_date_display(trip.get("end_date"))
        trip["visibility"] = trip.get("visibility", "private")

        member_rows = (
            supabase.table("trip_members")
            .select("user_id,role,users(id,name,email)")
            .eq("trip_id", trip_id)
            .order("role", desc=True)
            .execute()
            .data
        )
        members = [
            {
                "name": relation_to_object(row.get("users")).get("name", "Unknown"),
                "email": relation_to_object(row.get("users")).get("email", "-"),
                "role": row.get("role", "member"),
                "user_id": row.get("user_id"),
            }
            for row in member_rows
        ]

        bookings = fetch_trip_bookings(supabase, trip_id)
        custom_field_keys = set()
        for booking in bookings:
            booking["start_date_display"] = format_date_display(booking.get("start_date"))
            booking["end_date_display"] = format_date_display(booking.get("end_date"))
            fields = booking.get("custom_fields") or {}
            if isinstance(fields, dict):
                custom_field_keys.update(fields.keys())
            booking["custom_fields_text"] = custom_fields_to_text(fields)

        custom_field_columns = sorted(custom_field_keys)
        current_user_role = get_trip_role(trip_id, session["user_id"])
        owner_candidates = [
            m for m in members if m.get("user_id") != session["user_id"] and m.get("role") != "owner"
        ]

        return render_template(
            "trip_details.html",
            trip=trip,
            members=members,
            bookings=bookings,
            sectors=SECTORS,
            custom_field_columns=custom_field_columns,
            current_user_role=current_user_role,
            can_manage_roles=current_user_role == "owner",
            can_edit_bookings=current_user_role in {"owner", "member"},
            can_open_links=current_user_role != "observer",
            assignable_roles=ASSIGNABLE_ROLES,
            current_user_id=session["user_id"],
            owner_candidates=owner_candidates,
        )

    @app.route("/trips/<int:trip_id>/invite", methods=["POST"])
    @login_required
    def invite_member(trip_id):
        role = get_trip_role(trip_id, session["user_id"])
        if role != "owner":
            flash("Only the trip owner can invite and assign roles.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        email = request.form.get("email", "").strip().lower()
        invite_role = request.form.get("invite_role", "member").strip().lower()
        if invite_role not in ASSIGNABLE_ROLES:
            flash("Invalid invite role.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        supabase = get_supabase()

        trip = _first(supabase.table("trips").select("id,title").eq("id", trip_id).limit(1).execute().data)
        inviter_name = session.get("user_name", "A trip organizer")
        trip_title = trip.get("title", "your trip") if trip else "your trip"

        user = _first(supabase.table("users").select("id").eq("email", email).limit(1).execute().data)
        if user:
            supabase.table("notifications").insert(
                {
                    "user_id": user["id"],
                    "trip_id": trip_id,
                    "type": "trip_invite",
                    "message": "You have been invited to a trip. Accept or deny.",
                    "status": "pending",
                    "invite_role": invite_role,
                }
            ).execute()
            flash("Invitation sent as in-app notification.", "success")
        else:
            try:
                invite = _first(
                    supabase.table("pending_invites")
                    .upsert(
                        {
                            "trip_id": trip_id,
                            "email": email,
                            "invited_by": session["user_id"],
                            "status": "pending",
                            "invite_role": invite_role,
                        },
                        on_conflict="trip_id,email",
                    )
                    .execute()
                    .data
                )
            except Exception:
                logger.exception("Failed storing pending invite for %s", email)
                flash("Could not store invitation. Please try again.", "danger")
                return redirect(url_for("trip_details", trip_id=trip_id))

            email_sent = send_signup_invite_email(email, inviter_name, trip_title)

            if invite and email_sent:
                try:
                    supabase.table("pending_invites").update(
                        {"email_sent_at": datetime.utcnow().isoformat()}
                    ).eq("id", invite["id"]).execute()
                except Exception:
                    logger.exception("Failed updating email_sent_at for pending invite %s", invite.get("id"))
                flash("Invite stored and email sent successfully.", "success")
            elif email_sent:
                flash("Invite email sent successfully.", "success")
            else:
                flash("Invite stored, but email could not be sent. Configure SMTP env vars.", "warning")

        return redirect(url_for("trip_details", trip_id=trip_id))

    @app.route("/trips/<int:trip_id>/bookings", methods=["POST"])
    @login_required
    def add_booking(trip_id):
        role = get_trip_role(trip_id, session["user_id"])
        if role is None:
            flash("You do not have access to this trip.", "danger")
            return redirect(url_for("dashboard"))
        if role == "observer":
            flash("Observers cannot modify bookings.", "warning")
            return redirect(url_for("trip_details", trip_id=trip_id))

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

        get_supabase().table("bookings").insert(
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

    @app.route("/trips/<int:trip_id>/bookings/<int:booking_id>/edit", methods=["POST"])
    @login_required
    def edit_booking(trip_id, booking_id):
        role = get_trip_role(trip_id, session["user_id"])
        if role is None:
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
            flash("Sector, title, and start date are required for edits.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))
        if start_date_raw and not start_date:
            flash("Use dd/mm/yyyy format for booking start date.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))
        if end_date_raw and not end_date:
            flash("Use dd/mm/yyyy format for booking end date.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        supabase = get_supabase()
        existing = _first(
            supabase.table("bookings")
            .select("id")
            .eq("id", booking_id)
            .eq("trip_id", trip_id)
            .limit(1)
            .execute()
            .data
        )
        if not existing:
            flash("Booking not found.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        supabase.table("bookings").update(
            {
                "sector": sector,
                "title": title,
                "provider": provider,
                "confirmation_code": confirmation_code,
                "start_date": start_date,
                "end_date": end_date,
                "notes": notes,
                "custom_fields": custom_fields,
            }
        ).eq("id", booking_id).eq("trip_id", trip_id).execute()

        flash("Booking updated.", "success")
        return redirect(url_for("trip_details", trip_id=trip_id))


    @app.route("/trips/<int:trip_id>/members/<int:member_user_id>/role", methods=["POST"])
    @login_required
    def update_member_role(trip_id, member_user_id):
        role = get_trip_role(trip_id, session["user_id"])
        if role != "owner":
            flash("Only owner can manage participant roles.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        new_role = request.form.get("role", "").strip().lower()
        if new_role not in ASSIGNABLE_ROLES:
            flash("Invalid role selection.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        target_role = get_trip_role(trip_id, member_user_id)
        if target_role is None:
            flash("Participant not found.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))
        if target_role == "owner":
            flash("Owner role cannot be changed.", "warning")
            return redirect(url_for("trip_details", trip_id=trip_id))

        get_supabase().table("trip_members").update({"role": new_role}).eq("trip_id", trip_id).eq("user_id", member_user_id).execute()
        flash("Participant role updated.", "success")
        return redirect(url_for("trip_details", trip_id=trip_id))

    @app.route("/trips/<int:trip_id>/leave", methods=["POST"])
    @login_required
    def leave_trip(trip_id):
        role = get_trip_role(trip_id, session["user_id"])
        if role is None:
            flash("You are not a participant of this trip.", "warning")
            return redirect(url_for("dashboard"))

        supabase = get_supabase()
        if role == "owner":
            new_owner_user_id = request.form.get("new_owner_user_id", "").strip()
            if not new_owner_user_id.isdigit():
                flash("Select a participant to transfer ownership before leaving.", "warning")
                return redirect(url_for("trip_details", trip_id=trip_id))

            target_id = int(new_owner_user_id)
            if target_id == session["user_id"]:
                flash("Owner transfer target must be another participant.", "warning")
                return redirect(url_for("trip_details", trip_id=trip_id))

            target_role = get_trip_role(trip_id, target_id)
            if target_role is None:
                flash("Selected participant is not in this trip.", "danger")
                return redirect(url_for("trip_details", trip_id=trip_id))

            supabase.table("trip_members").update({"role": "owner"}).eq("trip_id", trip_id).eq("user_id", target_id).execute()

        supabase.table("trip_members").delete().eq("trip_id", trip_id).eq("user_id", session["user_id"]).execute()
        flash("You left the trip.", "info")
        return redirect(url_for("dashboard"))


    @app.route("/friends/request", methods=["POST"])
    @login_required
    def send_friend_request():
        email = request.form.get("email", "").strip().lower()
        supabase = get_supabase()
        target = _first(supabase.table("users").select("id,name").eq("email", email).limit(1).execute().data)
        if not target:
            flash("User not found.", "danger")
            return redirect(url_for("feed"))
        if target["id"] == session["user_id"]:
            flash("You cannot friend yourself.", "warning")
            return redirect(url_for("feed"))

        friend_ids = get_friend_ids(session["user_id"])
        if target["id"] in friend_ids:
            flash("Already friends.", "info")
            return redirect(url_for("feed"))

        req = _first(
            supabase.table("friend_requests")
            .upsert(
                {"requester_id": session["user_id"], "addressee_id": target["id"], "status": "pending"},
                on_conflict="requester_id,addressee_id",
            )
            .execute()
            .data
        )

        if req:
            supabase.table("notifications").insert(
                {
                    "user_id": target["id"],
                    "type": "friend_request",
                    "message": f"{session.get('user_name', 'Someone')} sent you a friend request.",
                    "status": "pending",
                    "friend_request_id": req["id"],
                }
            ).execute()

        flash("Friend request sent.", "success")
        return redirect(url_for("feed"))

    @app.route("/trips/<int:trip_id>/join-public", methods=["POST"])
    @login_required
    def join_public_trip(trip_id):
        supabase = get_supabase()
        trip = _first(supabase.table("trips").select("id,visibility").eq("id", trip_id).limit(1).execute().data)
        if not trip or trip.get("visibility") != "public":
            flash("Trip is not public.", "warning")
            return redirect(url_for("feed"))

        supabase.table("trip_members").upsert(
            {"trip_id": trip_id, "user_id": session["user_id"], "role": "observer"},
            on_conflict="trip_id,user_id",
        ).execute()
        flash("Joined trip as observer.", "success")
        return redirect(url_for("trip_details", trip_id=trip_id))

    @app.route("/trips/<int:trip_id>/request-access", methods=["POST"])
    @login_required
    def request_private_trip_access(trip_id):
        supabase = get_supabase()
        trip = _first(supabase.table("trips").select("id,title,visibility,created_by").eq("id", trip_id).limit(1).execute().data)
        if not trip:
            flash("Trip not found.", "danger")
            return redirect(url_for("feed"))
        if trip.get("visibility") == "public":
            return redirect(url_for("join_public_trip", trip_id=trip_id))

        req = _first(
            supabase.table("join_requests")
            .upsert(
                {"trip_id": trip_id, "requester_id": session["user_id"], "status": "pending"},
                on_conflict="trip_id,requester_id",
            )
            .execute()
            .data
        )
        if req:
            supabase.table("notifications").insert(
                {
                    "user_id": trip["created_by"],
                    "trip_id": trip_id,
                    "type": "join_request",
                    "message": f"{session.get('user_name', 'Someone')} requested to join trip '{trip.get('title', '')}'.",
                    "status": "pending",
                    "join_request_id": req["id"],
                }
            ).execute()

        flash("Access request sent to owner.", "success")
        return redirect(url_for("feed"))

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        user_id = session["user_id"]
        ensure_profile(user_id)
        supabase = get_supabase()

        if request.method == "POST":
            bio = request.form.get("bio", "").strip() or None
            name_visibility = request.form.get("name_visibility", "friends").strip().lower()
            email_visibility = request.form.get("email_visibility", "private").strip().lower()
            bio_visibility = request.form.get("bio_visibility", "friends").strip().lower()
            if name_visibility not in VISIBILITY_LEVELS or email_visibility not in VISIBILITY_LEVELS or bio_visibility not in VISIBILITY_LEVELS:
                flash("Invalid visibility selection.", "danger")
                return redirect(url_for("profile"))

            supabase.table("profiles").update(
                {
                    "bio": bio,
                    "name_visibility": name_visibility,
                    "email_visibility": email_visibility,
                    "bio_visibility": bio_visibility,
                    "updated_at": datetime.utcnow().isoformat(),
                }
            ).eq("user_id", user_id).execute()
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))

        user = _first(supabase.table("users").select("id,name,email").eq("id", user_id).limit(1).execute().data) or {}
        profile_row = _first(supabase.table("profiles").select("*").eq("user_id", user_id).limit(1).execute().data) or {}
        friends = supabase.table("friendships").select("friend_id,users!friendships_friend_id_fkey(name,email)").eq("user_id", user_id).execute().data

        return render_template(
            "profile.html",
            user=user,
            profile_data=profile_row,
            visibility_levels=VISIBILITY_LEVELS,
            friends=friends,
        )

    return app
