import os

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import g


def get_database_url():
    database_url = os.getenv("SUPABASE_DB_URL") or os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "Missing database URL. Set SUPABASE_DB_URL (preferred) or DATABASE_URL."
        )
    return database_url


def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(get_database_url(), cursor_factory=RealDictCursor)
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = psycopg2.connect(get_database_url(), cursor_factory=RealDictCursor)
    with db:
        with db.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS trips (
                    id BIGSERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    start_date DATE,
                    end_date DATE,
                    created_by BIGINT NOT NULL REFERENCES users(id),
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS trip_members (
                    trip_id BIGINT NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
                    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    role TEXT DEFAULT 'member',
                    added_at TIMESTAMPTZ DEFAULT NOW(),
                    PRIMARY KEY (trip_id, user_id)
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS bookings (
                    id BIGSERIAL PRIMARY KEY,
                    trip_id BIGINT NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
                    sector TEXT NOT NULL,
                    title TEXT NOT NULL,
                    provider TEXT,
                    confirmation_code TEXT,
                    booking_date DATE,
                    notes TEXT,
                    created_by BIGINT NOT NULL REFERENCES users(id),
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                """
            )
    db.close()
