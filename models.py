# ============================================================
# SMART PATIENT ASSISTANCE AND EMERGENCY ALERT SYSTEM
# DATABASE MODELS
# ============================================================

import sqlite3
from pathlib import Path


class _ClosingSQLiteConnection(sqlite3.Connection):
    """Commit/rollback normally while ensuring ``with`` also releases the handle."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


# ============================================================
# PROJECT DIRECTORY
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"

DATABASE_FILE = DATA_DIR / "smart_patient_assistance.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    """
    Create and return a SQLite database connection.

    sqlite3.Row allows database records to be accessed using
    column names, for example:

        row["username"]
        row["password_hash"]
        row["status"]
    """

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_FILE,
        timeout=30,
        factory=_ClosingSQLiteConnection,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    connection.execute(
        "PRAGMA busy_timeout = 30000"
    )

    return connection


# ============================================================
# CREATE DATABASE
# ============================================================

def create_database():
    """
    Create all database tables required by main backend.

    This function creates only the tables and fields that are
    required by the current backend code.
    """

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = get_connection()
    cursor = connection.cursor()

    try:

        # ====================================================
        # ADMIN
        # ====================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin (
                admin_id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                recovery_key_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'ADMIN',
                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Migration for databases created before roles were introduced.
        columns = [row["name"] for row in cursor.execute("PRAGMA table_info(admin)")]
        if "role" not in columns:
            cursor.execute("ALTER TABLE admin ADD COLUMN role TEXT NOT NULL DEFAULT 'ADMIN'")
        # Older builds used SYSTEM_USER for the second administrator.
        cursor.execute("UPDATE admin SET role = 'ADMIN' WHERE role = 'SYSTEM_USER'")


        # ====================================================
        # WARDS
        # ====================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wards (
                ward_id TEXT PRIMARY KEY,
                ward_type TEXT NOT NULL
            )
        """)


        # ====================================================
        # BEDS
        # ====================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS beds (
                bed_id TEXT PRIMARY KEY,
                ward_id TEXT NOT NULL,
                status TEXT NOT NULL
                    DEFAULT 'Available',

                FOREIGN KEY (ward_id)
                    REFERENCES wards(ward_id)
                    ON UPDATE CASCADE
                    ON DELETE RESTRICT
            )
        """)


        # ====================================================
        # PATIENTS
        # ====================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patients (
                patient_id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                age TEXT NOT NULL DEFAULT '',
                gender TEXT NOT NULL DEFAULT '',
                phone TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT ''
            )
        """)
        patient_columns = {row["name"] for row in cursor.execute("PRAGMA table_info(patients)")}
        for column in ("name", "age", "gender", "phone", "notes"):
            if column not in patient_columns:
                cursor.execute(f"ALTER TABLE patients ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")


        # ====================================================
        # STAFF
        # ====================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS staff (
                staff_id TEXT PRIMARY KEY
            )
        """)


        # ====================================================
        # PATIENT ASSIGNMENTS
        # ====================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patient_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                bed_id TEXT NOT NULL,
                patient_id TEXT NOT NULL,
                staff_id TEXT NOT NULL,

                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                updated_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (bed_id)
                    REFERENCES beds(bed_id)
                    ON UPDATE CASCADE
                    ON DELETE RESTRICT,

                FOREIGN KEY (patient_id)
                    REFERENCES patients(patient_id)
                    ON UPDATE CASCADE
                    ON DELETE RESTRICT,

                FOREIGN KEY (staff_id)
                    REFERENCES staff(staff_id)
                    ON UPDATE CASCADE
                    ON DELETE RESTRICT,

                UNIQUE (bed_id),

                UNIQUE (patient_id)
            )
        """)


        # ====================================================
        # DEVICES
        # ====================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,

                status TEXT NOT NULL
                    DEFAULT 'Offline',

                last_seen TEXT
            )
        """)


        # ====================================================
        # DEVICE ASSIGNMENTS
        # ====================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                device_id TEXT NOT NULL,
                ward_id TEXT NOT NULL,
                bed_id TEXT NOT NULL,

                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                updated_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (device_id)
                    REFERENCES devices(device_id)
                    ON UPDATE CASCADE
                    ON DELETE CASCADE,

                FOREIGN KEY (ward_id)
                    REFERENCES wards(ward_id)
                    ON UPDATE CASCADE
                    ON DELETE RESTRICT,

                FOREIGN KEY (bed_id)
                    REFERENCES beds(bed_id)
                    ON UPDATE CASCADE
                    ON DELETE RESTRICT,

                UNIQUE (device_id),

                UNIQUE (bed_id)
            )
        """)


        # ====================================================
        # ALERTS
        # ====================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                device_id TEXT,
                ward_id TEXT,
                bed_id TEXT,

                patient_id TEXT,
                staff_id TEXT,

                alert_type TEXT NOT NULL,

                alert_status TEXT NOT NULL
                    DEFAULT 'ACTIVE',

                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                attended_at TEXT,
                source TEXT NOT NULL DEFAULT 'UNVERIFIED',

                FOREIGN KEY (device_id)
                    REFERENCES devices(device_id)
                    ON UPDATE CASCADE
                    ON DELETE SET NULL,

                FOREIGN KEY (ward_id)
                    REFERENCES wards(ward_id)
                    ON UPDATE CASCADE
                    ON DELETE SET NULL,

                FOREIGN KEY (bed_id)
                    REFERENCES beds(bed_id)
                    ON UPDATE CASCADE
                    ON DELETE SET NULL,

                FOREIGN KEY (patient_id)
                    REFERENCES patients(patient_id)
                    ON UPDATE CASCADE
                    ON DELETE SET NULL,

                FOREIGN KEY (staff_id)
                    REFERENCES staff(staff_id)
                    ON UPDATE CASCADE
                    ON DELETE SET NULL
            )
        """)
        alert_columns = {row["name"] for row in cursor.execute("PRAGMA table_info(alerts)")}
        if "source" not in alert_columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN source TEXT NOT NULL DEFAULT 'UNVERIFIED'")
        for column in ("receiver_id", "event_type", "event_id"):
            if column not in alert_columns:
                cursor.execute(f"ALTER TABLE alerts ADD COLUMN {column} TEXT")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id) WHERE event_id IS NOT NULL")


        # ====================================================
        # SYSTEM LOGS
        # ====================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                event_type TEXT NOT NULL,

                description TEXT NOT NULL,

                device_id TEXT,
                ward_id TEXT,
                bed_id TEXT,
                patient_id TEXT,

                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (device_id)
                    REFERENCES devices(device_id)
                    ON UPDATE CASCADE
                    ON DELETE SET NULL,

                FOREIGN KEY (ward_id)
                    REFERENCES wards(ward_id)
                    ON UPDATE CASCADE
                    ON DELETE SET NULL,

                FOREIGN KEY (bed_id)
                    REFERENCES beds(bed_id)
                    ON UPDATE CASCADE
                    ON DELETE SET NULL,

                FOREIGN KEY (patient_id)
                    REFERENCES patients(patient_id)
                    ON UPDATE CASCADE
                    ON DELETE SET NULL
            )
        """)


        # ====================================================
        # INDEXES
        # ====================================================

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_patient_assignments_bed
            ON patient_assignments(bed_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_patient_assignments_patient
            ON patient_assignments(patient_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_patient_assignments_staff
            ON patient_assignments(staff_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_device_assignments_device
            ON device_assignments(device_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_device_assignments_ward
            ON device_assignments(ward_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_device_assignments_bed
            ON device_assignments(bed_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alerts_created_at
            ON alerts(created_at)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alerts_status
            ON alerts(alert_status)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alerts_type
            ON alerts(alert_type)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alerts_ward
            ON alerts(ward_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alerts_bed
            ON alerts(bed_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alerts_device
            ON alerts(device_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_system_logs_created_at
            ON system_logs(created_at)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_system_logs_event_type
            ON system_logs(event_type)
        """)


        # ====================================================
        # COMMIT
        # ====================================================

        connection.commit()

    except Exception:

        connection.rollback()
        raise

    finally:

        connection.close()


# ============================================================
# DATABASE PATH
# ============================================================

def get_database_path():
    """
    Return the full path to the SQLite database.
    """

    return DATABASE_FILE


# ============================================================
# DATABASE TABLE LIST
# ============================================================

def get_database_tables():
    """
    Return the names of all database tables.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        ORDER BY name
    """)

    rows = cursor.fetchall()

    connection.close()

    return [
        row["name"]
        for row in rows
    ]


# ============================================================
# DATABASE TEST
# ============================================================

if __name__ == "__main__":

    print(
        "=============================================="
    )

    print(
        "SMART PATIENT ASSISTANCE AND "
        "EMERGENCY ALERT SYSTEM"
    )

    print(
        "DATABASE INITIALIZATION"
    )

    print(
        "=============================================="
    )

    create_database()

    print(
        "Database initialized successfully."
    )

    print(
        f"Database:"
    )

    print(
        DATABASE_FILE
    )

    print(
        "\nTables:"
    )

    for table in get_database_tables():

        print(
            f"  - {table}"
        )

    print(
        "=============================================="
    )
