import sqlite3
from pathlib import Path

from app.config import DATABASE_PATH


def get_connection() -> sqlite3.Connection:
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    schema_path = Path(__file__).resolve().parents[2] / "database" / "schema.sql"
    with get_connection() as connection:
        connection.executescript(schema_path.read_text())
