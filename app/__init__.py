from collections import defaultdict
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session

from .db import get_db, close_db, init_db
from .auth import login_required


SECTORS = ["stay", "flight", "attraction"]


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

            db = get_db()
            exists = db.execute("SELECT id FROM users WHERE email = %s", (email,)).fetchone()
            if exists:
                flash("User with this email already exists.", "danger")
                return redirect(url_for("register"))

            db.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s)",
                (name, email, generate_password_hash(password)),
            )
            db.commit()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            db = get_db()
            user = db.execute("SELECT * FROM users WHERE email = %s", (email,)).fetchone()
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
        db = get_db()
        trips = db.execute(
            """
            SELECT t.*
            FROM trips t
            INNER JOIN trip_members tm ON tm.trip_id = t.id
            WHERE tm.user_id = %s
            ORDER BY t.start_date IS NULL, t.start_date, t.created_at DESC
            """,
            (user_id,),
        ).fetchall()

        bookings = db.execute(
            """
            SELECT b.*, t.title AS trip_title
            FROM bookings b
            INNER JOIN trips t ON t.id = b.trip_id
            INNER JOIN trip_members tm ON tm.trip_id = t.id
            WHERE tm.user_id = %s
            ORDER BY b.created_at DESC
            """,
            (user_id,),
        ).fetchall()

        by_sector = defaultdict(list)
        for booking in bookings:
            by_sector[booking["sector"]].append(booking)

        return render_template("dashboard.html", trips=trips, by_sector=by_sector, sectors=SECTORS)

    @app.route("/trips/new", methods=["POST"])
    @login_required
    def create_trip():
        title = request.form.get("title", "").strip()
        destination = request.form.get("destination", "").strip()
        start_date = request.form.get("start_date", "")
        end_date = request.form.get("end_date", "")

        if not title or not destination:
            flash("Trip title and destination are required.", "danger")
            return redirect(url_for("dashboard"))

        db = get_db()
        cur = db.execute(
            """
            INSERT INTO trips (title, destination, start_date, end_date, created_by)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (title, destination, start_date or None, end_date or None, session["user_id"]),
        )
        trip_id = cur.fetchone()["id"]
        db.execute(
            "INSERT INTO trip_members (trip_id, user_id, role) VALUES (%s, %s, 'owner')",
            (trip_id, session["user_id"]),
        )
        db.commit()
        flash("Trip created.", "success")
        return redirect(url_for("trip_details", trip_id=trip_id))

    def ensure_member(trip_id, user_id):
        db = get_db()
        member = db.execute(
            "SELECT 1 FROM trip_members WHERE trip_id = %s AND user_id = %s",
            (trip_id, user_id),
        ).fetchone()
        return member is not None

    @app.route("/trips/<int:trip_id>")
    @login_required
    def trip_details(trip_id):
        if not ensure_member(trip_id, session["user_id"]):
            flash("You do not have access to this trip.", "danger")
            return redirect(url_for("dashboard"))

        db = get_db()
        trip = db.execute("SELECT * FROM trips WHERE id = %s", (trip_id,)).fetchone()
        members = db.execute(
            """
            SELECT u.name, u.email, tm.role
            FROM trip_members tm
            INNER JOIN users u ON u.id = tm.user_id
            WHERE tm.trip_id = %s
            ORDER BY tm.role DESC, u.name
            """,
            (trip_id,),
        ).fetchall()
        bookings = db.execute(
            "SELECT * FROM bookings WHERE trip_id = %s ORDER BY booking_date IS NULL, booking_date, created_at DESC",
            (trip_id,),
        ).fetchall()

        return render_template("trip_details.html", trip=trip, members=members, bookings=bookings, sectors=SECTORS)

    @app.route("/trips/<int:trip_id>/invite", methods=["POST"])
    @login_required
    def invite_member(trip_id):
        if not ensure_member(trip_id, session["user_id"]):
            flash("You do not have access to invite users for this trip.", "danger")
            return redirect(url_for("dashboard"))

        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE email = %s", (email,)).fetchone()
        if not user:
            flash("User not found. Ask them to register first.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        db.execute(
            """
            INSERT INTO trip_members (trip_id, user_id, role)
            VALUES (%s, %s, 'member')
            ON CONFLICT (trip_id, user_id) DO NOTHING
            """,
            (trip_id, user["id"]),
        )
        db.commit()
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
        provider = request.form.get("provider", "").strip()
        confirmation_code = request.form.get("confirmation_code", "").strip()
        booking_date = request.form.get("booking_date", "").strip()
        notes = request.form.get("notes", "").strip()

        if sector not in SECTORS or not title:
            flash("Booking sector and title are required.", "danger")
            return redirect(url_for("trip_details", trip_id=trip_id))

        db = get_db()
        db.execute(
            """
            INSERT INTO bookings (trip_id, sector, title, provider, confirmation_code, booking_date, notes, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (trip_id, sector, title, provider or None, confirmation_code or None, booking_date or None, notes or None, session["user_id"]),
        )
        db.commit()
        flash("Booking added.", "success")
        return redirect(url_for("trip_details", trip_id=trip_id))

    return app
