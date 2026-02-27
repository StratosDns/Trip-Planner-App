import os

from flask import g
from supabase import create_client


def get_supabase():
    if "supabase" not in g:
        supabase_url = os.getenv("SUPABASE_URL")
        supabase_key = os.getenv("SUPABASE_ANON_KEY") or os.getenv("SUPABASE_KEY")

        if not supabase_url or not supabase_key:
            raise RuntimeError(
                "Missing Supabase credentials. Set SUPABASE_URL and SUPABASE_ANON_KEY."
            )

        g.supabase = create_client(supabase_url, supabase_key)
    return g.supabase


def close_db(_=None):
    g.pop("supabase", None)


def init_db():
    # Schema management is expected to be handled in Supabase migrations/SQL editor.
    # This app validates connectivity when first query is executed.
    return None
