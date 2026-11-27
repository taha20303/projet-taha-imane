import os
from contextlib import contextmanager

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

load_dotenv()


def get_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        client_encoding="UTF8",  # WIN1252 casse les caractères non latins
    )


@contextmanager
def db_cursor(dict_rows=False):
    """Valide la transaction, annule en cas d'erreur, puis ferme TOUJOURS
    la connexion (le `with conn` de psycopg2 ne la ferme pas)."""
    conn = get_connection()
    try:
        factory = RealDictCursor if dict_rows else None
        with conn.cursor(cursor_factory=factory) as cursor:
            yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db_cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS public.transfer_logs (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100),
                filename VARCHAR(255),
                destination VARCHAR(255),
                file_size BIGINT,
                sensitivity VARCHAR(50),
                decision VARCHAR(20),
                decision_reason TEXT,
                risk_score INTEGER,
                risk_level VARCHAR(20),
                anomaly BOOLEAN,          -- NULL = analyse ML indisponible
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Pour une table déjà créée avec DEFAULT FALSE :
        cursor.execute(
            "ALTER TABLE public.transfer_logs "
            "ALTER COLUMN anomaly DROP DEFAULT;"
        )


def save_transfer(data):
    anomaly = data.get("anomaly")
    anomaly = None if anomaly is None else bool(anomaly)  # None reste None

    with db_cursor() as cursor:
        cursor.execute("""
            INSERT INTO public.transfer_logs (
                username, filename, destination, file_size,
                sensitivity, decision, decision_reason,
                risk_score, risk_level, anomaly
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id;
        """, (
            data["username"],
            data["filename"],
            data["destination"],
            data["file_size"],
            data["sensitivity"],
            data["decision"],
            data["decision_reason"],
            data["risk_score"],
            data["risk_level"],
            anomaly,
        ))
        return cursor.fetchone()[0]


def count_recent_user_transfers(username):
    with db_cursor() as cursor:
        cursor.execute("""
            SELECT COUNT(*)
            FROM public.transfer_logs
            WHERE username = %s
              AND created_at >= NOW() - INTERVAL '1 hour';
        """, (username,))
        return cursor.fetchone()[0]


def get_recent_transfers(limit=50):
    with db_cursor(dict_rows=True) as cursor:
        cursor.execute("""
            SELECT *
            FROM public.transfer_logs
            ORDER BY created_at DESC
            LIMIT %s;
        """, (limit,))
        return cursor.fetchall()