# ============================================================
# SMART PATIENT ASSISTANCE AND EMERGENCY ALERT SYSTEM
# MAIN BACKEND
# ============================================================

import sys
import sqlite3
import json
import hashlib
import secrets
import threading
import time
import shutil
import os

from pathlib import Path
from datetime import datetime, timedelta
from calendar import monthrange
from services.serial_service import SerialService

# ============================================================
# INSTALLED PACKAGES
# ============================================================

# USB / Serial communication
import serial
import serial.tools.list_ports

# Bluetooth communication
from bleak import BleakScanner, BleakClient

# PDF generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak
)
from reportlab.lib.units import mm

# Charts and statistics
import matplotlib.pyplot as plt

# Password/security utilities
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

# ============================================================
# PROJECT MODULES
# ============================================================

from models import create_database, get_connection

# ============================================================
# PROJECT DIRECTORIES
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
ASSETS_DIR = BASE_DIR / "assets"
BACKUPS_DIR = BASE_DIR / "backups"

# ============================================================
# DATABASE FILE
# ============================================================

DATABASE_FILE = DATA_DIR / "smart_patient_assistance.db"

# ============================================================
# SYSTEM INFORMATION
# ============================================================

APP_NAME = (
    "Smart Patient Assistance and Emergency Alert System"
)

APP_VERSION = "1.0.0"

# ============================================================
# REPORT CONFIGURATION
# ============================================================

REPORT_TITLE = (
    "SMART PATIENT ASSISTANCE AND "
    "EMERGENCY ALERT SYSTEM"
)

# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_backend():
    """
    Initialize the backend database and required directories.
    """

    DATA_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    ASSETS_DIR.mkdir(exist_ok=True)
    BACKUPS_DIR.mkdir(exist_ok=True)

    create_database()

    print("Database initialized successfully.")


# ============================================================
# ADMIN ACCOUNT CHECK
# ============================================================

def admin_exists():
    """Return whether at least one administrator account has been configured."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT admin_id
        FROM admin
        LIMIT 1
    """)

    result = cursor.fetchone()

    connection.close()

    return result is not None


# ============================================================
# ADMIN ACCOUNT INFORMATION
# ============================================================

def get_admin(username=None):
    """
    Retrieve an administrator account.  When no username is supplied, return
    the oldest account for compatibility with the account-settings screen.
    """

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        SELECT
            admin_id,
            username,
            password_hash,
            recovery_key_hash,
            role,
            created_at,
            updated_at
        FROM admin
    """
    if username is not None:
        query += " WHERE username = ?"
    query += " ORDER BY admin_id LIMIT 1"
    cursor.execute(query, (str(username).strip(),) if username is not None else ())

    admin = cursor.fetchone()

    connection.close()

    return admin


# ============================================================
# FIRST-TIME ADMIN SETUP
# ============================================================

def create_admin(username, password, recovery_key):
    """
    Create an administrator account (the application supports up to two).
    """

    username = username.strip()

    if not username:
        return False, "Username cannot be empty."

    if not password:
        return False, "Password cannot be empty."

    if not recovery_key:
        return False, "Recovery key cannot be empty."

    password_hash = generate_password_hash(password)
    recovery_key_hash = generate_password_hash(recovery_key)

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("BEGIN IMMEDIATE")
        cursor.execute("SELECT COUNT(*) AS count FROM admin")
        if cursor.fetchone()["count"] >= 1:
            connection.close()
            return False, "First-time setup is available only before the first administrator is created."

        cursor.execute("""
            INSERT INTO admin (
                username,
                password_hash,
                recovery_key_hash,
                role
            )
            VALUES (?, ?, ?, 'ADMIN')
        """, (
            username,
            password_hash,
            recovery_key_hash
        ))

        connection.commit()

    except sqlite3.IntegrityError as error:

        connection.rollback()
        connection.close()

        return False, (
            f"Unable to create administrator: {error}"
        )

    connection.close()

    return True, "Administrator account created successfully."


def create_additional_admin(username, password, recovery_key):
    """Create a second administrator after authenticated UI approval."""
    username = str(username).strip()
    if not username or not password or not recovery_key:
        return False, "Username, password and recovery key are required."
    if (len(password) < 8 or not any(char.islower() for char in password)
            or not any(char.isupper() for char in password)
            or not any(char.isdigit() for char in password)
            or not any(not char.isalnum() for char in password)):
        return False, "Password needs 8+ characters with uppercase, lowercase, number and special character."
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        cursor.execute("SELECT COUNT(*) AS count FROM admin")
        if cursor.fetchone()["count"] >= 2:
            return False, "Only two administrator accounts are permitted."
        cursor.execute(
            "INSERT INTO admin (username, password_hash, recovery_key_hash, role) VALUES (?, ?, ?, 'ADMIN')",
            (username, generate_password_hash(password), generate_password_hash(recovery_key)),
        )
        connection.commit()
        return True, "Administrator account created successfully."
    except sqlite3.IntegrityError:
        connection.rollback()
        return False, "That administrator username is already in use."
    finally:
        connection.close()


# ============================================================
# ADMIN LOGIN
# ============================================================

def login_admin(username, password):
    """
    Verify administrator login credentials.
    """

    admin = get_admin(username)

    if admin is None:
        return False, "First-Time Setup is required."

    if username.strip() != admin["username"]:
        return False, "Invalid username or password."

    if not check_password_hash(
        admin["password_hash"],
        password
    ):
        return False, "Invalid username or password."

    return True, "Login successful."


# ============================================================
# VERIFY CURRENT PASSWORD
# ============================================================

def verify_current_password(password):
    """
    Verify the administrator's current password.
    """

    admin = get_admin()

    if admin is None:
        return False

    return check_password_hash(
        admin["password_hash"],
        password
    )


# ============================================================
# VERIFY CURRENT USERNAME
# ============================================================

def verify_current_username(username):
    """
    Verify the administrator's current username.
    """

    admin = get_admin()

    if admin is None:
        return False

    return username.strip() == admin["username"]


# ============================================================
# VERIFY RECOVERY KEY
# ============================================================

def verify_recovery_key(recovery_key):
    """
    Verify the administrator's recovery key.
    """

    admin = get_admin()

    if admin is None:
        return False

    return check_password_hash(
        admin["recovery_key_hash"],
        recovery_key
    )


# ============================================================
# CHANGE PASSWORD
# ============================================================

def change_password(
    current_password,
    new_password,
    confirm_password
):
    """
    Change administrator password.
    """

    if not verify_current_password(current_password):
        return False, "Current password is incorrect."

    if not new_password:
        return False, "New password cannot be empty."

    if new_password != confirm_password:
        return False, "New passwords do not match."

    new_password_hash = generate_password_hash(new_password)

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE admin
        SET
            password_hash = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE admin_id = 1
    """, (new_password_hash,))

    connection.commit()
    connection.close()

    return True, "Password changed successfully."


# ============================================================
# CHANGE USERNAME
# ============================================================

def change_username(
    current_username,
    new_username,
    confirm_username
):
    """
    Change administrator username.
    """

    if not verify_current_username(current_username):
        return False, "Current username is incorrect."

    new_username = new_username.strip()
    confirm_username = confirm_username.strip()

    if not new_username:
        return False, "New username cannot be empty."

    if new_username != confirm_username:
        return False, "New usernames do not match."

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute("""
            UPDATE admin
            SET
                username = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE admin_id = 1
        """, (new_username,))

        connection.commit()

    except sqlite3.IntegrityError:

        connection.rollback()
        connection.close()

        return False, "That username cannot be used."

    connection.close()

    return True, "Username changed successfully."


# ============================================================
# RESET PASSWORD USING RECOVERY KEY
# ============================================================

def reset_password(
    recovery_key,
    new_password,
    confirm_password
):
    """
    Reset administrator password using recovery key.
    """

    if not verify_recovery_key(recovery_key):
        return False, "Recovery key is incorrect."

    if not new_password:
        return False, "New password cannot be empty."

    if new_password != confirm_password:
        return False, "New passwords do not match."

    new_password_hash = generate_password_hash(new_password)

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE admin
        SET
            password_hash = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE admin_id = 1
    """, (new_password_hash,))

    connection.commit()
    connection.close()

    return True, "Password reset successfully."


# ============================================================
# CHANGE RECOVERY KEY
# ============================================================

def change_recovery_key(
    current_recovery_key,
    new_recovery_key,
    confirm_recovery_key
):
    """
    Change administrator recovery key.
    """

    if not verify_recovery_key(current_recovery_key):
        return False, "Current recovery key is incorrect."

    if not new_recovery_key:
        return False, "New recovery key cannot be empty."

    if new_recovery_key != confirm_recovery_key:
        return False, "New recovery keys do not match."

    new_recovery_key_hash = generate_password_hash(
        new_recovery_key
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE admin
        SET
            recovery_key_hash = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE admin_id = 1
    """, (new_recovery_key_hash,))

    connection.commit()
    connection.close()

    return True, "Recovery key changed successfully."


# ============================================================
# PATIENT MANAGEMENT
# ============================================================

def assign_patient_to_bed(
    bed_id,
    patient_id,
    staff_id
):
    """
    Assign a patient and nurse/doctor to a bed.
    """

    bed_id = str(bed_id).strip()
    patient_id = str(patient_id).strip()
    staff_id = str(staff_id).strip()

    if not bed_id:
        return False, "Bed ID is required."

    if not patient_id:
        return False, "Patient ID is required."

    if not staff_id:
        return False, "Nurse / Doctor ID is required."

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT bed_id, status
        FROM beds
        WHERE bed_id = ?
    """, (bed_id,))

    bed = cursor.fetchone()

    if bed is None:
        connection.close()
        return False, "Bed ID does not exist."

    cursor.execute("""
        SELECT patient_id
        FROM patients
        WHERE patient_id = ?
    """, (patient_id,))

    if cursor.fetchone() is None:
        connection.close()
        return False, "Patient ID does not exist."

    cursor.execute("""
        SELECT staff_id
        FROM staff
        WHERE staff_id = ?
    """, (staff_id,))

    if cursor.fetchone() is None:
        connection.close()
        return False, "Nurse / Doctor ID does not exist."

    cursor.execute("""
        SELECT bed_id
        FROM patient_assignments
        WHERE patient_id = ?
          AND bed_id != ?
    """, (
        patient_id,
        bed_id
    ))

    if cursor.fetchone() is not None:
        connection.close()
        return False, (
            "This patient is already assigned to another bed."
        )

    cursor.execute("""
        SELECT id
        FROM patient_assignments
        WHERE bed_id = ?
    """, (bed_id,))

    existing = cursor.fetchone()

    try:

        if existing:

            cursor.execute("""
                UPDATE patient_assignments
                SET
                    patient_id = ?,
                    staff_id = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE bed_id = ?
            """, (
                patient_id,
                staff_id,
                bed_id
            ))

        else:

            cursor.execute("""
                INSERT INTO patient_assignments (
                    bed_id,
                    patient_id,
                    staff_id
                )
                VALUES (?, ?, ?)
            """, (
                bed_id,
                patient_id,
                staff_id
            ))

        cursor.execute("""
            UPDATE beds
            SET status = 'Occupied'
            WHERE bed_id = ?
        """, (bed_id,))

        connection.commit()

    except sqlite3.IntegrityError as error:

        connection.rollback()
        connection.close()

        return False, (
            f"Unable to assign patient: {error}"
        )

    connection.close()

    return True, "Patient assigned to bed successfully."


# ============================================================
# UPDATE PATIENT BED
# ============================================================

def update_patient_bed(
    current_bed_id,
    new_bed_id,
    patient_id,
    staff_id
):
    """
    Move a patient from one bed to another.
    """

    current_bed_id = str(current_bed_id).strip()
    new_bed_id = str(new_bed_id).strip()
    patient_id = str(patient_id).strip()
    staff_id = str(staff_id).strip()

    if not current_bed_id:
        return False, "Current bed ID is required."

    if not new_bed_id:
        return False, "New bed ID is required."

    if not patient_id:
        return False, "Patient ID is required."

    if not staff_id:
        return False, "Nurse / Doctor ID is required."

    if current_bed_id == new_bed_id:
        return False, (
            "New bed must be different from current bed."
        )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM patient_assignments
        WHERE bed_id = ?
          AND patient_id = ?
    """, (
        current_bed_id,
        patient_id
    ))

    if cursor.fetchone() is None:
        connection.close()
        return False, (
            "Current patient assignment was not found."
        )

    cursor.execute("""
        SELECT bed_id, status
        FROM beds
        WHERE bed_id = ?
    """, (new_bed_id,))

    new_bed = cursor.fetchone()

    if new_bed is None:
        connection.close()
        return False, "New bed ID does not exist."

    cursor.execute("""
        SELECT id
        FROM patient_assignments
        WHERE bed_id = ?
    """, (new_bed_id,))

    if cursor.fetchone() is not None:
        connection.close()
        return False, "The new bed already has a patient."

    try:

        cursor.execute("""
            DELETE FROM patient_assignments
            WHERE bed_id = ?
              AND patient_id = ?
        """, (
            current_bed_id,
            patient_id
        ))

        cursor.execute("""
            UPDATE beds
            SET status = 'Available'
            WHERE bed_id = ?
        """, (current_bed_id,))

        cursor.execute("""
            INSERT INTO patient_assignments (
                bed_id,
                patient_id,
                staff_id
            )
            VALUES (?, ?, ?)
        """, (
            new_bed_id,
            patient_id,
            staff_id
        ))

        cursor.execute("""
            UPDATE beds
            SET status = 'Occupied'
            WHERE bed_id = ?
        """, (new_bed_id,))

        connection.commit()

    except sqlite3.IntegrityError as error:

        connection.rollback()
        connection.close()

        return False, (
            f"Unable to move patient: {error}"
        )

    connection.close()

    return True, "Patient moved successfully."


# ============================================================
# DISCHARGE PATIENT
# ============================================================

def discharge_patient(
    bed_id,
    patient_id
):
    """
    Discharge a patient from a bed.
    """

    bed_id = str(bed_id).strip()
    patient_id = str(patient_id).strip()

    if not bed_id:
        return False, "Bed ID is required."

    if not patient_id:
        return False, "Patient ID is required."

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM patient_assignments
        WHERE bed_id = ?
          AND patient_id = ?
    """, (
        bed_id,
        patient_id
    ))

    if cursor.fetchone() is None:
        connection.close()
        return False, (
            "Patient assignment was not found."
        )

    try:

        cursor.execute("""
            DELETE FROM patient_assignments
            WHERE bed_id = ?
              AND patient_id = ?
        """, (
            bed_id,
            patient_id
        ))

        cursor.execute("""
            UPDATE beds
            SET status = 'Available'
            WHERE bed_id = ?
        """, (bed_id,))

        connection.commit()

    except sqlite3.Error as error:

        connection.rollback()
        connection.close()

        return False, (
            f"Unable to discharge patient: {error}"
        )

    connection.close()

    return True, "Patient discharged successfully."


# ============================================================
# GET PATIENT ASSIGNMENTS
# ============================================================

def get_patient_assignments():
    """
    Return all current patient-bed assignments.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            pa.id,
            pa.bed_id,
            pa.patient_id,
            pa.staff_id,
            pa.created_at,
            pa.updated_at,
            b.status AS bed_status
        FROM patient_assignments pa
        LEFT JOIN beds b
            ON pa.bed_id = b.bed_id
        ORDER BY pa.bed_id
    """)

    rows = cursor.fetchall()

    connection.close()

    return rows


# ============================================================
# GET AVAILABLE BEDS
# ============================================================

def get_available_beds(
    ward_id=None
):
    """
    Return available beds.
    """

    connection = get_connection()
    cursor = connection.cursor()

    if ward_id:

        cursor.execute("""
            SELECT
                bed_id,
                ward_id,
                status
            FROM beds
            WHERE ward_id = ?
              AND status = 'Available'
            ORDER BY bed_id
        """, (str(ward_id).strip(),))

    else:

        cursor.execute("""
            SELECT
                bed_id,
                ward_id,
                status
            FROM beds
            WHERE status = 'Available'
            ORDER BY bed_id
        """)

    rows = cursor.fetchall()

    connection.close()

    return rows


# ============================================================
# DEVICE–BED MANAGEMENT
# ============================================================

def assign_device_to_bed(
    device_id,
    ward_id,
    ward_type,
    bed_id
):
    """
    Assign an ESP32 patient device to:

        Device
          ↓
        Ward
          ↓
        Ward Type
          ↓
        Bed

    The Hall Receiver is NOT handled by this function.
    """

    device_id = str(device_id).strip()
    ward_id = str(ward_id).strip()
    ward_type = str(ward_type).strip()
    bed_id = str(bed_id).strip()

    if not device_id:
        return False, "Device ID is required."

    if not ward_id:
        return False, "Ward ID is required."

    if not ward_type:
        return False, "Ward type is required."

    if not bed_id:
        return False, "Bed ID is required."

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT device_id
        FROM devices
        WHERE device_id = ?
    """, (device_id,))

    if cursor.fetchone() is None:
        connection.close()
        return False, "Device does not exist."

    cursor.execute("""
        SELECT ward_id, ward_type
        FROM wards
        WHERE ward_id = ?
    """, (ward_id,))

    ward = cursor.fetchone()

    if ward is None:
        connection.close()
        return False, "Ward ID does not exist."

    if ward["ward_type"] != ward_type:
        connection.close()
        return False, (
            "Selected ward type does not match the ward."
        )

    cursor.execute("""
        SELECT bed_id
        FROM beds
        WHERE bed_id = ?
          AND ward_id = ?
    """, (
        bed_id,
        ward_id
    ))

    if cursor.fetchone() is None:
        connection.close()
        return False, (
            "Bed does not belong to the selected ward."
        )

    cursor.execute("""
        SELECT id, bed_id
        FROM device_assignments
        WHERE device_id = ?
    """, (device_id,))

    existing_device = cursor.fetchone()

    cursor.execute("""
        SELECT device_id
        FROM device_assignments
        WHERE bed_id = ?
    """, (bed_id,))

    existing_bed = cursor.fetchone()

    if existing_bed and (
        existing_device is None
        or existing_bed["device_id"] != device_id
    ):
        connection.close()
        return False, (
            "This bed is already assigned to another device."
        )

    try:

        if existing_device:

            cursor.execute("""
                UPDATE device_assignments
                SET
                    ward_id = ?,
                    bed_id = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE device_id = ?
            """, (
                ward_id,
                bed_id,
                device_id
            ))

        else:

            cursor.execute("""
                INSERT INTO device_assignments (
                    device_id,
                    ward_id,
                    bed_id
                )
                VALUES (?, ?, ?)
            """, (
                device_id,
                ward_id,
                bed_id
            ))

        connection.commit()

    except sqlite3.IntegrityError as error:

        connection.rollback()
        connection.close()

        return False, (
            f"Unable to assign device: {error}"
        )

    connection.close()

    return True, "Device assigned to bed successfully."


# ============================================================
# UPDATE DEVICE–BED ASSIGNMENT
# ============================================================

def update_device_bed(
    device_id,
    new_ward_id,
    new_ward_type,
    new_bed_id
):
    """
    Update the ward and bed assigned to an ESP32 device.
    """

    device_id = str(device_id).strip()
    new_ward_id = str(new_ward_id).strip()
    new_ward_type = str(new_ward_type).strip()
    new_bed_id = str(new_bed_id).strip()

    if not device_id:
        return False, "Device ID is required."

    if not new_ward_id:
        return False, "Ward ID is required."

    if not new_ward_type:
        return False, "Ward type is required."

    if not new_bed_id:
        return False, "Bed ID is required."

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT device_id
        FROM devices
        WHERE device_id = ?
    """, (device_id,))

    if cursor.fetchone() is None:
        connection.close()
        return False, "ESP32 device does not exist."

    cursor.execute("""
        SELECT ward_id, ward_type
        FROM wards
        WHERE ward_id = ?
    """, (new_ward_id,))

    ward = cursor.fetchone()

    if ward is None:
        connection.close()
        return False, "Ward ID does not exist."

    if ward["ward_type"] != new_ward_type:
        connection.close()
        return False, (
            "Selected ward type does not match the ward."
        )

    cursor.execute("""
        SELECT bed_id
        FROM beds
        WHERE bed_id = ?
          AND ward_id = ?
    """, (
        new_bed_id,
        new_ward_id
    ))

    if cursor.fetchone() is None:
        connection.close()
        return False, (
            "Bed does not belong to the selected ward."
        )

    cursor.execute("""
        SELECT device_id
        FROM device_assignments
        WHERE bed_id = ?
          AND device_id != ?
    """, (
        new_bed_id,
        device_id
    ))

    if cursor.fetchone() is not None:
        connection.close()
        return False, (
            "The new bed is already assigned "
            "to another device."
        )

    try:

        cursor.execute("""
            UPDATE device_assignments
            SET
                ward_id = ?,
                bed_id = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE device_id = ?
        """, (
            new_ward_id,
            new_bed_id,
            device_id
        ))

        if cursor.rowcount == 0:
            connection.close()
            return False, (
                "Device assignment was not found."
            )

        connection.commit()

    except sqlite3.IntegrityError as error:

        connection.rollback()
        connection.close()

        return False, (
            f"Unable to update device assignment: {error}"
        )

    connection.close()

    return True, (
        "Device-bed assignment updated successfully."
    )


# ============================================================
# GET DEVICE ASSIGNMENTS
# ============================================================

def get_device_assignments():
    """
    Return the current Device → Ward → Bed assignments.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            da.id,
            da.device_id,
            da.ward_id,
            w.ward_type,
            da.bed_id,
            d.status,
            d.last_seen,
            da.created_at,
            da.updated_at
        FROM device_assignments da

        LEFT JOIN devices d
            ON da.device_id = d.device_id

        LEFT JOIN wards w
            ON da.ward_id = w.ward_id

        ORDER BY da.ward_id, da.bed_id
    """)

    rows = cursor.fetchall()

    connection.close()

    return rows


# ============================================================
# REPORTS
# ============================================================

def get_report_styles():
    """
    Create styles used by all system reports.
    """

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitleCustom",
            parent=styles["Title"],
            fontSize=18,
            leading=22,
            alignment=TA_CENTER,
            spaceAfter=8
        )
    )

    styles.add(
        ParagraphStyle(
            name="ReportSubtitleCustom",
            parent=styles["Normal"],
            fontSize=12,
            leading=15,
            alignment=TA_CENTER,
            spaceAfter=12
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeadingCustom",
            parent=styles["Heading2"],
            fontSize=12,
            leading=15,
            alignment=TA_LEFT,
            spaceBefore=10,
            spaceAfter=6
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallTextCustom",
            parent=styles["Normal"],
            fontSize=8,
            leading=10
        )
    )

    return styles


# ============================================================
# REPORT DATE RANGE
# ============================================================

def get_report_period(
    report_type,
    report_date=None
):
    """
    Determine reporting period.

    Supported:
        daily
        weekly
        monthly
    """

    if report_date is None:
        report_date = datetime.now()

    if isinstance(report_date, str):
        report_date = datetime.strptime(
            report_date,
            "%Y-%m-%d"
        )

    report_type = report_type.lower()

    if report_type == "daily":

        start = report_date.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )

        end = start + timedelta(
            days=1,
            seconds=-1
        )

    elif report_type == "weekly":

        start = (
            report_date
            - timedelta(days=report_date.weekday())
        ).replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )

        end = start + timedelta(
            days=7,
            seconds=-1
        )

    elif report_type == "monthly":

        start = report_date.replace(
            day=1,
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )

        last_day = monthrange(
            start.year,
            start.month
        )[1]

        end = start.replace(
            day=last_day,
            hour=23,
            minute=59,
            second=59
        )

    else:
        raise ValueError(
            "Invalid report type. "
            "Use daily, weekly or monthly."
        )

    return start, end


# ============================================================
# GET ALERT SUMMARY
# ============================================================

def get_alert_summary(start, end):
    """
    Get alert totals for a reporting period.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            alert_type,
            COUNT(*) AS total,

            SUM(
                CASE
                    WHEN alert_status = 'ATTENDED'
                    THEN 1
                    ELSE 0
                END
            ) AS attended,

            SUM(
                CASE
                    WHEN alert_status = 'CANCELLED'
                    THEN 1
                    ELSE 0
                END
            ) AS cancelled,

            SUM(
                CASE
                    WHEN alert_status = 'ACTIVE'
                    THEN 1
                    ELSE 0
                END
            ) AS active

        FROM alerts

        WHERE datetime(created_at)
              BETWEEN datetime(?)
              AND datetime(?)

        GROUP BY alert_type
        ORDER BY alert_type
    """, (
        start.strftime("%Y-%m-%d %H:%M:%S"),
        end.strftime("%Y-%m-%d %H:%M:%S")
    ))

    rows = cursor.fetchall()

    connection.close()

    return rows


# ============================================================
# GET TOTAL ALERTS
# ============================================================

def get_total_alerts(start, end):
    """
    Return total alerts during reporting period.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM alerts
        WHERE datetime(created_at)
              BETWEEN datetime(?)
              AND datetime(?)
    """, (
        start.strftime("%Y-%m-%d %H:%M:%S"),
        end.strftime("%Y-%m-%d %H:%M:%S")
    ))

    result = cursor.fetchone()

    connection.close()

    return result["total"] if result else 0


# ============================================================
# GET RESPONSE INFORMATION
# ============================================================

def get_response_information(start, end):
    """
    Calculate response information.

    Response time:
        created_at → attended_at
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            device_id,
            ward_id,
            bed_id,
            patient_id,
            staff_id,
            alert_type,
            alert_status,
            created_at,
            attended_at,

            CASE
                WHEN attended_at IS NOT NULL
                THEN (
                    strftime(
                        '%s',
                        attended_at
                    )
                    -
                    strftime(
                        '%s',
                        created_at
                    )
                )
                ELSE NULL
            END AS response_seconds

        FROM alerts

        WHERE datetime(created_at)
              BETWEEN datetime(?)
              AND datetime(?)

        ORDER BY datetime(created_at) DESC
    """, (
        start.strftime("%Y-%m-%d %H:%M:%S"),
        end.strftime("%Y-%m-%d %H:%M:%S")
    ))

    rows = cursor.fetchall()

    connection.close()

    return rows


# ============================================================
# RESPONSE TIME FORMAT
# ============================================================

def format_response_time(seconds):
    """
    Convert seconds to HH:MM:SS.
    """

    if seconds is None:
        return "—"

    seconds = max(0, int(seconds))

    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    remaining_seconds = seconds % 60

    return (
        f"{hours:02d}:"
        f"{minutes:02d}:"
        f"{remaining_seconds:02d}"
    )


# ============================================================
# GET WARD ALERT STATISTICS
# ============================================================

def get_ward_statistics(start, end):
    """
    Get alert statistics grouped by ward.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            ward_id,

            COUNT(*) AS total,

            SUM(
                CASE
                    WHEN alert_status = 'ATTENDED'
                    THEN 1
                    ELSE 0
                END
            ) AS attended,

            SUM(
                CASE
                    WHEN alert_status = 'CANCELLED'
                    THEN 1
                    ELSE 0
                END
            ) AS cancelled,

            SUM(
                CASE
                    WHEN alert_status = 'ACTIVE'
                    THEN 1
                    ELSE 0
                END
            ) AS active

        FROM alerts

        WHERE datetime(created_at)
              BETWEEN datetime(?)
              AND datetime(?)

        GROUP BY ward_id
        ORDER BY ward_id
    """, (
        start.strftime("%Y-%m-%d %H:%M:%S"),
        end.strftime("%Y-%m-%d %H:%M:%S")
    ))

    rows = cursor.fetchall()

    connection.close()

    return rows


# ============================================================
# GET SYSTEM FUNCTIONING
# ============================================================

def get_system_functioning():
    """
    Retrieve current condition of all registered ESP32 devices.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            d.device_id,
            da.ward_id,
            da.bed_id,
            d.status,
            d.last_seen

        FROM devices d

        LEFT JOIN device_assignments da
            ON d.device_id = da.device_id

        ORDER BY d.device_id
    """)

    devices = cursor.fetchall()

    connection.close()

    result = []

    for device in devices:

        status = device["status"]

        if status == "Online":
            issue = "Normal"

        elif status == "Offline":
            issue = "No communication"

        else:
            issue = "Device issue"

        result.append({
            "device_id": device["device_id"],
            "ward_id": device["ward_id"] or "—",
            "bed_id": device["bed_id"] or "—",
            "status": status,
            "issue": issue,
            "last_seen": device["last_seen"] or "—"
        })

    return result


# ============================================================
# GET SYSTEM ISSUE LOGS
# ============================================================

def get_system_issues(start, end):
    """
    Retrieve system events/issues recorded during
    reporting period.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            event_type,
            description,
            device_id,
            ward_id,
            bed_id,
            patient_id,
            created_at

        FROM system_logs

        WHERE datetime(created_at)
              BETWEEN datetime(?)
              AND datetime(?)

        ORDER BY datetime(created_at) DESC
    """, (
        start.strftime("%Y-%m-%d %H:%M:%S"),
        end.strftime("%Y-%m-%d %H:%M:%S")
    ))

    rows = cursor.fetchall()

    connection.close()

    return rows


# ============================================================
# CREATE REPORT TABLE HELPER
# ============================================================

def create_report_table(
    data,
    column_widths=None,
    header=True
):
    """
    Create professionally formatted ReportLab table.
    """

    table = Table(
        data,
        colWidths=column_widths,
        repeatRows=1 if header else 0,
        hAlign="LEFT"
    )

    table_style = [
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.5,
            colors.grey
        ),
        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "MIDDLE"
        ),
        (
            "LEFTPADDING",
            (0, 0),
            (-1, -1),
            5
        ),
        (
            "RIGHTPADDING",
            (0, 0),
            (-1, -1),
            5
        ),
        (
            "TOPPADDING",
            (0, 0),
            (-1, -1),
            5
        ),
        (
            "BOTTOMPADDING",
            (0, 0),
            (-1, -1),
            5
        )
    ]

    if header:

        table_style.extend([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, 0),
                "CENTER"
            )
        ])

    table.setStyle(
        TableStyle(table_style)
    )

    return table


# ============================================================
# REPORT HEADER
# ============================================================

def add_report_header(
    story,
    styles,
    report_type,
    start,
    end
):
    """
    Add standard report header.
    """

    story.append(
        Paragraph(
            REPORT_TITLE,
            styles["ReportTitleCustom"]
        )
    )

    story.append(
        Paragraph(
            f"{report_type.upper()} REPORT",
            styles["ReportSubtitleCustom"]
        )
    )

    information = [
        [
            "Report Type",
            report_type.capitalize()
        ],
        [
            "Reporting Period",
            f"{start.strftime('%d %B %Y %H:%M')} "
            f"to "
            f"{end.strftime('%d %B %Y %H:%M')}"
        ],
        [
            "Generated On",
            datetime.now().strftime(
                "%d %B %Y %H:%M:%S"
            )
        ],
        [
            "Generated By",
            REPORT_TITLE
        ]
    ]

    story.append(
        create_report_table(
            information,
            column_widths=[
                45 * mm,
                130 * mm
            ],
            header=False
        )
    )

    story.append(
        Spacer(1, 8)
    )


# ============================================================
# DAILY / WEEKLY / MONTHLY REPORT
# ============================================================

def generate_period_report(
    report_type,
    output_file,
    report_date=None
):
    """
    Generate Daily, Weekly or Monthly report.
    """

    start, end = get_report_period(
        report_type,
        report_date
    )

    styles = get_report_styles()

    document = SimpleDocTemplate(
        str(output_file),
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm
    )

    story = []

    add_report_header(
        story,
        styles,
        report_type,
        start,
        end
    )

    story.append(
        Paragraph(
            "ALERT SUMMARY",
            styles["SectionHeadingCustom"]
        )
    )

    alert_rows = [
        [
            "Alert Type",
            "Total",
            "Attended",
            "Cancelled",
            "Active"
        ]
    ]

    summaries = get_alert_summary(
        start,
        end
    )

    for row in summaries:

        alert_rows.append([
            row["alert_type"],
            row["total"] or 0,
            row["attended"] or 0,
            row["cancelled"] or 0,
            row["active"] or 0
        ])

    if len(alert_rows) == 1:

        alert_rows.append([
            "No alerts recorded",
            0,
            0,
            0,
            0
        ])

    story.append(
        create_report_table(
            alert_rows,
            column_widths=[
                55 * mm,
                30 * mm,
                30 * mm,
                30 * mm,
                30 * mm
            ]
        )
    )

    story.append(
        Paragraph(
            "RESPONSE PERFORMANCE",
            styles["SectionHeadingCustom"]
        )
    )

    response_rows = get_response_information(
        start,
        end
    )

    completed_times = [
        row["response_seconds"]
        for row in response_rows
        if row["response_seconds"] is not None
    ]

    if completed_times:

        average_response = (
            sum(completed_times)
            / len(completed_times)
        )

        fastest_response = min(
            completed_times
        )

        longest_response = max(
            completed_times
        )

    else:

        average_response = None
        fastest_response = None
        longest_response = None

    unattended = sum(
        1
        for row in response_rows
        if row["response_seconds"] is None
    )

    response_summary = [
        ["Metric", "Result"],
        [
            "Total Alerts",
            len(response_rows)
        ],
        [
            "Responded Alerts",
            len(completed_times)
        ],
        [
            "Average Response Time",
            format_response_time(
                average_response
            )
        ],
        [
            "Fastest Response",
            format_response_time(
                fastest_response
            )
        ],
        [
            "Longest Response",
            format_response_time(
                longest_response
            )
        ],
        [
            "Unattended Alerts",
            unattended
        ]
    ]

    story.append(
        create_report_table(
            response_summary,
            column_widths=[
                75 * mm,
                70 * mm
            ]
        )
    )

    story.append(
        Paragraph(
            "SYSTEM FUNCTIONING",
            styles["SectionHeadingCustom"]
        )
    )

    functioning = get_system_functioning()

    device_rows = [
        [
            "Device ID",
            "Ward ID",
            "Bed ID",
            "Status",
            "Issue / Condition",
            "Last Seen"
        ]
    ]

    for device in functioning:

        device_rows.append([
            device["device_id"],
            device["ward_id"],
            device["bed_id"],
            device["status"],
            device["issue"],
            device["last_seen"]
        ])

    if len(device_rows) == 1:

        device_rows.append([
            "No devices",
            "—",
            "—",
            "—",
            "—",
            "—"
        ])

    story.append(
        create_report_table(
            device_rows,
            column_widths=[
                30 * mm,
                30 * mm,
                30 * mm,
                30 * mm,
                65 * mm,
                45 * mm
            ]
        )
    )

    story.append(
        Paragraph(
            "SYSTEM ISSUES AND EVENTS",
            styles["SectionHeadingCustom"]
        )
    )

    issues = get_system_issues(
        start,
        end
    )

    issue_rows = [
        [
            "Date / Time",
            "Event",
            "Description",
            "Device ID",
            "Ward ID",
            "Bed ID"
        ]
    ]

    for issue in issues:

        issue_rows.append([
            issue["created_at"],
            issue["event_type"],
            issue["description"],
            issue["device_id"] or "—",
            issue["ward_id"] or "—",
            issue["bed_id"] or "—"
        ])

    if len(issue_rows) == 1:

        issue_rows.append([
            "—",
            "No Issues",
            "No recorded system issues/events",
            "—",
            "—",
            "—"
        ])

    story.append(
        create_report_table(
            issue_rows,
            column_widths=[
                35 * mm,
                35 * mm,
                85 * mm,
                30 * mm,
                30 * mm,
                30 * mm
            ]
        )
    )

    story.append(
        Paragraph(
            "WARD ALERT STATISTICS",
            styles["SectionHeadingCustom"]
        )
    )

    ward_rows = [
        [
            "Ward ID",
            "Total Alerts",
            "Attended",
            "Cancelled",
            "Active"
        ]
    ]

    ward_statistics = get_ward_statistics(
        start,
        end
    )

    for ward in ward_statistics:

        ward_rows.append([
            ward["ward_id"],
            ward["total"] or 0,
            ward["attended"] or 0,
            ward["cancelled"] or 0,
            ward["active"] or 0
        ])

    if len(ward_rows) == 1:

        ward_rows.append([
            "No ward activity",
            0,
            0,
            0,
            0
        ])

    story.append(
        create_report_table(
            ward_rows,
            column_widths=[
                50 * mm,
                35 * mm,
                35 * mm,
                35 * mm,
                35 * mm
            ]
        )
    )

    document.build(story)

    return output_file


# ============================================================
# DAILY REPORT
# ============================================================

def generate_daily_report(
    output_file=None,
    report_date=None
):
    """
    Generate Daily Report PDF.
    """

    if output_file is None:

        date_text = (
            report_date
            if isinstance(report_date, str)
            else datetime.now().strftime(
                "%Y-%m-%d"
            )
        )

        output_file = (
            REPORTS_DIR
            / f"daily_report_{date_text}.pdf"
        )

    return generate_period_report(
        "daily",
        output_file,
        report_date
    )


# ============================================================
# WEEKLY REPORT
# ============================================================

def generate_weekly_report(
    output_file=None,
    report_date=None
):
    """
    Generate Weekly Report PDF.
    """

    if output_file is None:

        date_text = datetime.now().strftime(
            "%Y-%m-%d"
        )

        output_file = (
            REPORTS_DIR
            / f"weekly_report_{date_text}.pdf"
        )

    return generate_period_report(
        "weekly",
        output_file,
        report_date
    )


# ============================================================
# MONTHLY REPORT
# ============================================================

def generate_monthly_report(
    output_file=None,
    report_date=None
):
    """
    Generate Monthly Report PDF.
    """

    if output_file is None:

        date_text = datetime.now().strftime(
            "%Y-%m"
        )

        output_file = (
            REPORTS_DIR
            / f"monthly_report_{date_text}.pdf"
        )

    return generate_period_report(
        "monthly",
        output_file,
        report_date
    )


# ============================================================
# RESPONSE REPORT
# ============================================================

def generate_response_report(
    output_file=None,
    start_date=None,
    end_date=None
):
    """
    Generate detailed Response Report PDF.
    """

    if start_date is None:

        start_date = datetime.now().replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )

    if end_date is None:

        end_date = datetime.now().replace(
            hour=23,
            minute=59,
            second=59,
            microsecond=0
        )

    if isinstance(start_date, str):

        start_date = datetime.strptime(
            start_date,
            "%Y-%m-%d"
        )

    if isinstance(end_date, str):

        end_date = datetime.strptime(
            end_date,
            "%Y-%m-%d"
        ).replace(
            hour=23,
            minute=59,
            second=59
        )

    if output_file is None:

        output_file = (
            REPORTS_DIR
            / "response_report.pdf"
        )

    styles = get_report_styles()

    document = SimpleDocTemplate(
        str(output_file),
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm
    )

    story = []

    add_report_header(
        story,
        styles,
        "Response",
        start_date,
        end_date
    )

    rows = get_response_information(
        start_date,
        end_date
    )

    response_table = [
        [
            "Alert ID",
            "Device ID",
            "Ward ID",
            "Bed ID",
            "Patient ID",
            "Staff ID",
            "Alert Type",
            "Created",
            "Attended",
            "Response Time"
        ]
    ]

    for row in rows:

        response_table.append([
            row["id"],
            row["device_id"],
            row["ward_id"],
            row["bed_id"],
            row["patient_id"] or "—",
            row["staff_id"] or "—",
            row["alert_type"],
            row["created_at"],
            row["attended_at"] or "—",
            format_response_time(
                row["response_seconds"]
            )
        ])

    if len(response_table) == 1:

        response_table.append([
            "—",
            "—",
            "—",
            "—",
            "—",
            "—",
            "No responses",
            "—",
            "—",
            "—"
        ])

    story.append(
        create_report_table(
            response_table,
            column_widths=[
                18 * mm,
                25 * mm,
                25 * mm,
                25 * mm,
                25 * mm,
                25 * mm,
                28 * mm,
                38 * mm,
                38 * mm,
                30 * mm
            ]
        )
    )

    document.build(story)

    return output_file


# ============================================================
# ALERT STATISTICS REPORT
# ============================================================

def generate_alert_statistics_report(
    output_file=None,
    start_date=None,
    end_date=None
):
    """
    Generate Alert Statistics PDF.
    """

    if start_date is None:

        start_date = datetime.now().replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )

    if end_date is None:

        end_date = datetime.now().replace(
            hour=23,
            minute=59,
            second=59,
            microsecond=0
        )

    if isinstance(start_date, str):

        start_date = datetime.strptime(
            start_date,
            "%Y-%m-%d"
        )

    if isinstance(end_date, str):

        end_date = datetime.strptime(
            end_date,
            "%Y-%m-%d"
        ).replace(
            hour=23,
            minute=59,
            second=59
        )

    if output_file is None:

        output_file = (
            REPORTS_DIR
            / "alert_statistics.pdf"
        )

    styles = get_report_styles()

    document = SimpleDocTemplate(
        str(output_file),
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm
    )

    story = []

    add_report_header(
        story,
        styles,
        "Alert Statistics",
        start_date,
        end_date
    )

    story.append(
        Paragraph(
            "ALERT TYPE STATISTICS",
            styles["SectionHeadingCustom"]
        )
    )

    summaries = get_alert_summary(
        start_date,
        end_date
    )

    statistics_table = [
        [
            "Alert Type",
            "Total",
            "Attended",
            "Cancelled",
            "Active"
        ]
    ]

    for row in summaries:

        statistics_table.append([
            row["alert_type"],
            row["total"] or 0,
            row["attended"] or 0,
            row["cancelled"] or 0,
            row["active"] or 0
        ])

    if len(statistics_table) == 1:

        statistics_table.append([
            "No alerts",
            0,
            0,
            0,
            0
        ])

    story.append(
        create_report_table(
            statistics_table,
            column_widths=[
                55 * mm,
                35 * mm,
                35 * mm,
                35 * mm,
                35 * mm
            ]
        )
    )

    story.append(
        Paragraph(
            "WARD ALERT STATISTICS",
            styles["SectionHeadingCustom"]
        )
    )

    ward_statistics = get_ward_statistics(
        start_date,
        end_date
    )

    ward_table = [
        [
            "Ward ID",
            "Total Alerts",
            "Attended",
            "Cancelled",
            "Active"
        ]
    ]

    for ward in ward_statistics:

        ward_table.append([
            ward["ward_id"],
            ward["total"] or 0,
            ward["attended"] or 0,
            ward["cancelled"] or 0,
            ward["active"] or 0
        ])

    if len(ward_table) == 1:

        ward_table.append([
            "No ward activity",
            0,
            0,
            0,
            0
        ])

    story.append(
        create_report_table(
            ward_table,
            column_widths=[
                50 * mm,
                35 * mm,
                35 * mm,
                35 * mm,
                35 * mm
            ]
        )
    )

    document.build(story)

    return output_file


# ============================================================
# GENERATE ALL REPORTS
# ============================================================

def generate_all_reports(
    report_date=None
):
    """
    Generate:

        Daily
        Weekly
        Monthly
        Response
        Alert Statistics
    """

    generated_files = []

    generated_files.append(
        generate_daily_report(
            report_date=report_date
        )
    )

    generated_files.append(
        generate_weekly_report(
            report_date=report_date
        )
    )

    generated_files.append(
        generate_monthly_report(
            report_date=report_date
        )
    )

    generated_files.append(
        generate_response_report()
    )

    generated_files.append(
        generate_alert_statistics_report()
    )

    return generated_files


# ============================================================
# SETTINGS
# ============================================================

SETTINGS_FILE = DATA_DIR / "system_settings.json"


DEFAULT_SETTINGS = {
    "hall_receiver": {
        "device_id": "HALL-001",
        "communication_enabled": True,
        "auto_reconnect": True
    },

    "device_communication": {
        "communication_enabled": True,
        "connection_timeout": 10,
        "reconnect_attempts": 3
    },

    "alert": {
        "assistance_alert_enabled": True,
        "emergency_alert_enabled": True,
        "critical_alert_enabled": True
    },

    "notification_sound": {
        "sound_enabled": True,
        "volume": 100,
        "repeat_sound": True,
        "repeat_interval": 5
    },

    "response_timing": {
        "response_timeout": 60,
        "alert_repeat_interval": 5
    },

    "startup": {
        "automatic_startup": False
    }
}


# ============================================================
# DEEP COPY DEFAULT SETTINGS
# ============================================================

def get_default_settings():
    """
    Return a fresh copy of default settings.
    """

    return json.loads(
        json.dumps(DEFAULT_SETTINGS)
    )


# ============================================================
# LOAD SETTINGS
# ============================================================

def load_settings():
    """
    Load system settings.

    If settings file does not exist,
    create it using default settings.
    """

    DATA_DIR.mkdir(exist_ok=True)

    if not SETTINGS_FILE.exists():

        settings = get_default_settings()

        save_settings(settings)

        return settings

    try:

        with open(
            SETTINGS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            settings = json.load(file)

        if not isinstance(settings, dict):
            raise ValueError(
                "Settings file must contain an object."
            )

        return settings

    except (
        json.JSONDecodeError,
        OSError,
        ValueError
    ):

        return get_default_settings()


# ============================================================
# SAVE SETTINGS
# ============================================================

def save_settings(settings):
    """
    Save system settings to JSON.
    """

    DATA_DIR.mkdir(exist_ok=True)

    temporary_file = SETTINGS_FILE.with_suffix(
        ".tmp"
    )

    with open(
        temporary_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            settings,
            file,
            indent=4
        )

    os.replace(
        temporary_file,
        SETTINGS_FILE
    )


# ============================================================
# UPDATE ONE SETTING
# ============================================================

def update_setting(
    section,
    setting,
    value
):
    """
    Update one system setting.
    """

    settings = load_settings()

    if section not in settings:
        raise ValueError(
            f"Unknown settings section: {section}"
        )

    if setting not in settings[section]:
        raise ValueError(
            f"Unknown setting: {setting}"
        )

    settings[section][setting] = value

    save_settings(settings)

    return settings


# ============================================================
# GET SYSTEM SETTINGS
# ============================================================

def get_system_settings():
    """
    Return all system settings.
    """

    return load_settings()


# ============================================================
# HALL RECEIVER SETTINGS
# ============================================================

def get_hall_receiver_settings():
    """
    Return Hall Receiver configuration.
    """

    settings = load_settings()

    return settings["hall_receiver"]


def update_hall_receiver_settings(
    device_id=None,
    communication_enabled=None,
    auto_reconnect=None
):
    """
    Update Hall Receiver configuration.

    IMPORTANT:
    The Hall Receiver is a separate system-level device.
    It is NOT assigned to a patient bed.
    """

    settings = load_settings()

    hall = settings["hall_receiver"]

    if device_id is not None:

        device_id = str(device_id).strip()

        if not device_id:
            raise ValueError(
                "Hall Receiver Device ID cannot be empty."
            )

        hall["device_id"] = device_id

    if communication_enabled is not None:

        hall["communication_enabled"] = bool(
            communication_enabled
        )

    if auto_reconnect is not None:

        hall["auto_reconnect"] = bool(
            auto_reconnect
        )

    save_settings(settings)

    return hall


# ============================================================
# DEVICE COMMUNICATION SETTINGS
# ============================================================

def get_device_communication_settings():
    """
    Return bed-device communication settings.
    """

    settings = load_settings()

    return settings["device_communication"]


def update_device_communication_settings(
    communication_enabled=None,
    connection_timeout=None,
    reconnect_attempts=None
):
    """
    Update communication settings for patient devices.
    """

    settings = load_settings()

    communication = settings[
        "device_communication"
    ]

    if communication_enabled is not None:

        communication[
            "communication_enabled"
        ] = bool(communication_enabled)

    if connection_timeout is not None:

        connection_timeout = int(
            connection_timeout
        )

        if connection_timeout <= 0:
            raise ValueError(
                "Connection timeout must be greater than zero."
            )

        communication[
            "connection_timeout"
        ] = connection_timeout

    if reconnect_attempts is not None:

        reconnect_attempts = int(
            reconnect_attempts
        )

        if reconnect_attempts < 0:
            raise ValueError(
                "Reconnect attempts cannot be negative."
            )

        communication[
            "reconnect_attempts"
        ] = reconnect_attempts

    save_settings(settings)

    return communication


# ============================================================
# ALERT SETTINGS
# ============================================================

def get_alert_settings():
    """
    Return alert configuration.
    """

    settings = load_settings()

    return settings["alert"]


def update_alert_settings(
    assistance_alert_enabled=None,
    emergency_alert_enabled=None,
    critical_alert_enabled=None
):
    """
    Update alert settings.
    """

    settings = load_settings()

    alert = settings["alert"]

    if assistance_alert_enabled is not None:

        alert[
            "assistance_alert_enabled"
        ] = bool(
            assistance_alert_enabled
        )

    if emergency_alert_enabled is not None:

        alert[
            "emergency_alert_enabled"
        ] = bool(
            emergency_alert_enabled
        )

    if critical_alert_enabled is not None:

        alert[
            "critical_alert_enabled"
        ] = bool(
            critical_alert_enabled
        )

    save_settings(settings)

    return alert


# ============================================================
# NOTIFICATION / SOUND SETTINGS
# ============================================================

def get_notification_sound_settings():
    """
    Return notification and sound settings.
    """

    settings = load_settings()

    return settings["notification_sound"]


def update_notification_sound_settings(
    sound_enabled=None,
    volume=None,
    repeat_sound=None,
    repeat_interval=None
):
    """
    Update notification and sound settings.
    """

    settings = load_settings()

    sound = settings[
        "notification_sound"
    ]

    if sound_enabled is not None:

        sound[
            "sound_enabled"
        ] = bool(sound_enabled)

    if volume is not None:

        volume = int(volume)

        if volume < 0 or volume > 100:
            raise ValueError(
                "Volume must be between 0 and 100."
            )

        sound["volume"] = volume

    if repeat_sound is not None:

        sound[
            "repeat_sound"
        ] = bool(repeat_sound)

    if repeat_interval is not None:

        repeat_interval = int(
            repeat_interval
        )

        if repeat_interval <= 0:
            raise ValueError(
                "Repeat interval must be greater than zero."
            )

        sound[
            "repeat_interval"
        ] = repeat_interval

    save_settings(settings)

    return sound


# ============================================================
# RESPONSE / ALERT TIMING SETTINGS
# ============================================================

def get_response_timing_settings():
    """
    Return response and alert timing settings.
    """

    settings = load_settings()

    return settings["response_timing"]


def update_response_timing_settings(
    response_timeout=None,
    alert_repeat_interval=None
):
    """
    Update response and alert timing settings.
    """

    settings = load_settings()

    timing = settings[
        "response_timing"
    ]

    if response_timeout is not None:

        response_timeout = int(
            response_timeout
        )

        if response_timeout <= 0:
            raise ValueError(
                "Response timeout must be greater than zero."
            )

        timing[
            "response_timeout"
        ] = response_timeout

    if alert_repeat_interval is not None:

        alert_repeat_interval = int(
            alert_repeat_interval
        )

        if alert_repeat_interval <= 0:
            raise ValueError(
                "Alert repeat interval must be greater than zero."
            )

        timing[
            "alert_repeat_interval"
        ] = alert_repeat_interval

    save_settings(settings)

    return timing


# ============================================================
# AUTOMATIC SYSTEM STARTUP
# ============================================================

def get_startup_settings():
    """
    Return automatic startup configuration.
    """

    settings = load_settings()

    return settings["startup"]


def update_startup_settings(
    automatic_startup
):
    """
    Enable or disable automatic system startup.
    """

    settings = load_settings()

    settings[
        "startup"
    ][
        "automatic_startup"
    ] = bool(
        automatic_startup
    )

    save_settings(settings)

    return settings["startup"]


# ============================================================
# SYSTEM LOGS
# ============================================================

def get_system_logs(
    limit=500,
    event_type=None
):
    """
    Retrieve system logs.
    """

    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 500

    if limit <= 0:
        limit = 500

    connection = get_connection()
    cursor = connection.cursor()

    if event_type:

        cursor.execute("""
            SELECT
                id,
                event_type,
                description,
                device_id,
                ward_id,
                bed_id,
                patient_id,
                created_at

            FROM system_logs

            WHERE event_type = ?

            ORDER BY datetime(created_at) DESC

            LIMIT ?
        """, (
            event_type,
            limit
        ))

    else:

        cursor.execute("""
            SELECT
                id,
                event_type,
                description,
                device_id,
                ward_id,
                bed_id,
                patient_id,
                created_at

            FROM system_logs

            ORDER BY datetime(created_at) DESC

            LIMIT ?
        """, (limit,))

    rows = cursor.fetchall()

    connection.close()

    return rows


# ============================================================
# ADD SYSTEM LOG
# ============================================================

def add_system_log(
    event_type,
    description,
    device_id=None,
    ward_id=None,
    bed_id=None,
    patient_id=None
):
    """
    Add an event to the system log.

    The database uses device_id consistently.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO system_logs (
            event_type,
            description,
            device_id,
            ward_id,
            bed_id,
            patient_id
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        event_type,
        description,
        device_id,
        ward_id,
        bed_id,
        patient_id
    ))

    connection.commit()

    connection.close()


# ============================================================
# BACKUP DATABASE
# ============================================================

def backup_database(
    destination=None
):
    """
    Create a backup copy of the SQLite database.
    """

    if not DATABASE_FILE.exists():

        raise FileNotFoundError(
            "Database file does not exist."
        )

    BACKUPS_DIR.mkdir(
        exist_ok=True
    )

    if destination is None:

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        destination = (
            BACKUPS_DIR
            /
            (
                "smart_patient_assistance_backup_"
                f"{timestamp}.db"
            )
        )

    else:

        destination = Path(
            destination
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    shutil.copy2(
        DATABASE_FILE,
        destination
    )

    return destination


# ============================================================
# RESTORE DATABASE
# ============================================================

def restore_database(
    backup_file
):
    """
    Restore system database from backup.

    A safety backup of the current database is created first.
    """

    backup_file = Path(
        backup_file
    )

    if not backup_file.exists():

        raise FileNotFoundError(
            "Selected backup file does not exist."
        )

    if backup_file.resolve() == DATABASE_FILE.resolve():

        raise ValueError(
            "The current database cannot be restored over itself."
        )

    safety_backup = backup_database()

    shutil.copy2(
        backup_file,
        DATABASE_FILE
    )

    return {
        "restored_from": str(
            backup_file
        ),
        "safety_backup": str(
            safety_backup
        )
    }


# ============================================================
# LIST DATABASE BACKUPS
# ============================================================

def list_backups():
    """
    Return all available database backups.
    """

    BACKUPS_DIR.mkdir(
        exist_ok=True
    )

    backups = []

    for file in sorted(
        BACKUPS_DIR.glob("*.db"),
        key=lambda item: item.stat().st_mtime,
        reverse=True
    ):

        backups.append({
            "file_name": file.name,
            "path": str(file),
            "size": file.stat().st_size,
            "created_at": datetime.fromtimestamp(
                file.stat().st_mtime
            ).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        })

    return backups


# ============================================================
# EXPORT SYSTEM SETTINGS
# ============================================================

def export_system_settings(
    destination
):
    """
    Export system settings to JSON.
    """

    destination = Path(
        destination
    )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    settings = load_settings()

    with open(
        destination,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            settings,
            file,
            indent=4
        )

    return destination


# ============================================================
# IMPORT SYSTEM SETTINGS
# ============================================================

def import_system_settings(
    source
):
    """
    Import system settings from JSON.
    """

    source = Path(
        source
    )

    if not source.exists():

        raise FileNotFoundError(
            "Settings file does not exist."
        )

    with open(
        source,
        "r",
        encoding="utf-8"
    ) as file:

        settings = json.load(file)

    if not isinstance(
        settings,
        dict
    ):

        raise ValueError(
            "Invalid system settings file."
        )

    required_sections = set(
        DEFAULT_SETTINGS.keys()
    )

    missing_sections = (
        required_sections
        - set(settings.keys())
    )

    if missing_sections:

        raise ValueError(
            "Invalid settings file. Missing sections: "
            + ", ".join(sorted(missing_sections))
        )

    save_settings(
        settings
    )

    return settings


# ============================================================
# SYSTEM STATUS
# ============================================================

def get_system_status():
    """
    Return basic backend status information.
    """

    return {
        "application": APP_NAME,
        "version": APP_VERSION,
        "database": str(DATABASE_FILE),
        "admin_configured": admin_exists(),
        "timestamp": datetime.now().isoformat()
    }


# ============================================================
# HALL RECEIVER / SERIAL COMMUNICATION
# ============================================================

_serial_service = None

_serial_lock = threading.Lock()

# Callback registered by the desktop UI.
# The UI can replace this using set_alert_callback().
_alert_callback = None


# ============================================================
# UI ALERT CALLBACK
# ============================================================

def set_alert_callback(callback):
    """
    Register a callback that will be called whenever
    a new patient alert is received.

    Example:

        set_alert_callback(ui.handle_new_alert)
    """

    global _alert_callback

    with _serial_lock:
        _alert_callback = callback


def _notify_alert_callback(alert):
    """
    Notify the desktop UI about a newly received alert.
    """

    with _serial_lock:
        callback = _alert_callback

    if callback is None:
        return

    try:
        callback(alert)

    except Exception as error:

        print(
            "Alert UI callback error:",
            error
        )


# ============================================================
# NORMALIZE HALL MESSAGE
# ============================================================

def _normalize_hall_message(message):
    """
    Convert a HallMessage object from serial_service.py
    into the dictionary format expected by main.py.

    This is important because SerialService sends:

        HallMessage(...)

    while the database functions in main.py use:

        dict
    """

    # --------------------------------------------------------
    # Already a dictionary
    # --------------------------------------------------------

    if isinstance(message, dict):

        return dict(message)

    # --------------------------------------------------------
    # HallMessage object
    # --------------------------------------------------------

    if hasattr(message, "__dataclass_fields__"):

        try:

            return {
                "message_type": message.message_type,

                "sender_device_id":
                    message.sender_device_id,

                "receiver_device_id":
                    message.receiver_device_id,

                "device_id":
                    message.sender_device_id,

                "ward_id":
                    message.ward_id,

                "bed_id":
                    message.bed_id,

                "patient_id":
                    message.patient_id,

                "staff_id":
                    message.staff_id,

                "alert_type":
                    message.alert_type,

                "alert_status":
                    message.alert_status,

                "timestamp":
                    message.timestamp,

                "received_at":
                    message.received_at,

                "payload":
                    message.payload,
            }

        except Exception as error:

            print(
                "Unable to normalize HallMessage:",
                error
            )

            return None

    # --------------------------------------------------------
    # Unknown object
    # --------------------------------------------------------

    print(
        "Unsupported Hall Receiver message type:",
        type(message)
    )

    return None


# ============================================================
# PROCESS RECEIVED PATIENT ALERT
# ============================================================

def process_received_patient_alert(message):
    """
    Process a patient alert received from the Hall Receiver.

    Communication path:

        Patient ESP32
             ↓
        LoRa transmitter
             ↓
        LoRa receiver
             ↓
        Hall ESP32
             ↓
        USB Serial
             ↓
        serial_service.py
             ↓
        this function
             ↓
        alerts table
             ↓
        Desktop UI
    """

    # --------------------------------------------------------
    # NORMALIZE MESSAGE
    # --------------------------------------------------------

    message = _normalize_hall_message(message)

    if message is None:

        print(
            "Ignoring invalid Hall Receiver message."
        )

        return None

    print(
        "Received Hall Receiver patient alert:",
        message
    )

    # --------------------------------------------------------
    # EXTRACT DEVICE INFORMATION
    # --------------------------------------------------------

    # SerialService creates "device_id" from the sender.
    #
    # We also support firmware that directly sends device_id.

    device_id = (
        message.get("device_id")
        or message.get("sender_device_id")
        or message.get("sender_id")
    )

    ward_id = message.get(
        "ward_id"
    )

    bed_id = message.get(
        "bed_id"
    )

    patient_id = message.get(
        "patient_id"
    )

    staff_id = message.get(
        "staff_id"
    )

    alert_type = (
        message.get("alert_type")
        or message.get("call_type")
        or message.get("alert")
    )

    # --------------------------------------------------------
    # BASIC VALIDATION
    # --------------------------------------------------------

    if not device_id:

        print(
            "Ignoring patient alert without device_id."
        )

        return None

    if not alert_type:

        # Some Hall ESP32 firmware may send PATIENT_ALERT
        # without an explicit alert_type.
        #
        # In that case use CALL as the default patient
        # assistance alert.

        message_type = str(
            message.get(
                "message_type",
                ""
            )
        ).strip().upper()

        if message_type in (
            "PATIENT_ALERT",
            "PATIENT_CALL",
            "ASSISTANCE",
            "EMERGENCY",
            "CRITICAL"
        ):

            alert_type = "CALL"

        else:

            print(
                "Ignoring alert without alert_type."
            )

            return None

    device_id = str(
        device_id
    ).strip()

    alert_type = str(
        alert_type
    ).strip()

    if not device_id or not alert_type:

        return None

    # --------------------------------------------------------
    # RESOLVE DEVICE → WARD → BED → PATIENT → STAFF
    # --------------------------------------------------------

    connection = get_connection()

    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            SELECT
                da.ward_id,
                da.bed_id,
                p.patient_id,
                pa.staff_id

            FROM device_assignments da

            LEFT JOIN patient_assignments pa
                ON da.bed_id = pa.bed_id

            LEFT JOIN patients p
                ON pa.patient_id = p.patient_id

            WHERE da.device_id = ?

            LIMIT 1
            """,
            (
                device_id,
            )
        )

        assignment = cursor.fetchone()

        if assignment:

            # ------------------------------------------------
            # Database assignment is authoritative.
            # ------------------------------------------------

            if not ward_id:

                ward_id = assignment["ward_id"]

            if not bed_id:

                bed_id = assignment["bed_id"]

            if not patient_id:

                patient_id = assignment["patient_id"]

            if not staff_id:

                staff_id = assignment["staff_id"]

        # ----------------------------------------------------
        # UPDATE DEVICE COMMUNICATION STATUS
        # ----------------------------------------------------

        cursor.execute(
            """
            UPDATE devices

            SET
                status = 'Online',
                last_seen = CURRENT_TIMESTAMP

            WHERE device_id = ?
            """,
            (
                device_id,
            )
        )

        # ----------------------------------------------------
        # INSERT PATIENT ALERT
        # ----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO alerts (
                device_id,
                ward_id,
                bed_id,
                patient_id,
                staff_id,
                alert_type,
                alert_status
            )

            VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
            """,
            (
                device_id,
                ward_id,
                bed_id,
                patient_id,
                staff_id,
                alert_type
            )
        )

        alert_id = cursor.lastrowid

        connection.commit()

    except sqlite3.Error as error:

        connection.rollback()

        print(
            "Failed to store received patient alert:",
            error
        )

        connection.close()

        return None

    except Exception as error:

        connection.rollback()

        print(
            "Unexpected error processing patient alert:",
            error
        )

        connection.close()

        return None

    connection.close()

    # --------------------------------------------------------
    # BUILD UI ALERT OBJECT
    # --------------------------------------------------------

    alert = {

        "id":
            alert_id,

        "device_id":
            device_id,

        "ward_id":
            ward_id,

        "bed_id":
            bed_id,

        "patient_id":
            patient_id,

        "staff_id":
            staff_id,

        "alert_type":
            alert_type,

        "alert_status":
            "ACTIVE",

        "created_at":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "raw_message":
            message,
    }

    # --------------------------------------------------------
    # SYSTEM LOG
    # --------------------------------------------------------

    try:

        add_system_log(

            event_type=
                "PATIENT_ALERT_RECEIVED",

            description=(
                f"Patient alert received from "
                f"device {device_id}: {alert_type}"
            ),

            device_id=
                device_id,

            ward_id=
                ward_id,

            bed_id=
                bed_id,

            patient_id=
                patient_id
        )

    except Exception as error:

        print(
            "Unable to create alert system log:",
            error
        )

    # --------------------------------------------------------
    # SEND ALERT TO DESKTOP UI
    # --------------------------------------------------------

    _notify_alert_callback(
        alert
    )

    print(
        "Patient alert stored successfully:",
        alert
    )

    return alert


# ============================================================
# HALL RECEIVER GENERAL MESSAGE
# ============================================================

def handle_hall_receiver_message(message):
    """
    Handle non-alert messages received from the Hall Receiver.

    IMPORTANT:

    PATIENT_ALERT messages are NOT processed here.

    SerialService already calls:

        on_patient_call()

    for patient alerts.

    This prevents the same alert from being inserted into
    the database twice.
    """

    # --------------------------------------------------------
    # NORMALIZE
    # --------------------------------------------------------

    message = _normalize_hall_message(
        message
    )

    if message is None:

        return

    # --------------------------------------------------------
    # DETERMINE MESSAGE TYPE
    # --------------------------------------------------------

    message_type = (
        message.get("message_type")
        or message.get("message")
        or message.get("type")
        or ""
    )

    message_type = str(
        message_type
    ).strip().upper()

    # --------------------------------------------------------
    # PATIENT ALERT
    #
    # DO NOT PROCESS HERE.
    #
    # SerialService will already call:
    #
    # process_received_patient_alert()
    #
    # through on_patient_call.
    # --------------------------------------------------------

    if message_type in (
        "PATIENT_CALL",
        "PATIENT_ALERT",
        "ASSISTANCE",
        "EMERGENCY",
        "CRITICAL",
        "CALL"
    ):

        return

    # --------------------------------------------------------
    # DEVICE INFORMATION
    # --------------------------------------------------------

    device_id = (
        message.get("device_id")
        or message.get("sender_device_id")
        or message.get("sender_id")
    )

    if device_id:

        device_id = str(
            device_id
        ).strip()

        connection = get_connection()

        cursor = connection.cursor()

        try:

            cursor.execute(
                """
                UPDATE devices

                SET
                    status = 'Online',
                    last_seen = CURRENT_TIMESTAMP

                WHERE device_id = ?
                """,
                (
                    device_id,
                )
            )

            connection.commit()

        except sqlite3.Error as error:

            connection.rollback()

            print(
                "Unable to update device communication:",
                error
            )

        finally:

            connection.close()

    # --------------------------------------------------------
    # LOG NON-ALERT COMMUNICATION
    # --------------------------------------------------------

    print(
        "Hall Receiver communication message:",
        message
    )


# ============================================================
# HALL RECEIVER USB CONNECTION CALLBACK
# ============================================================

def handle_hall_receiver_connection(connected):
    """
    Called whenever the USB connection to the Hall Receiver
    changes.
    """

    if connected:

        print(
            "Hall Receiver connected through USB."
        )

        try:

            add_system_log(

                event_type=
                    "HALL_RECEIVER_CONNECTED",

                description=(
                    "Hall Receiver ESP32 connected "
                    "through USB."
                )
            )

        except Exception as error:

            print(
                "Unable to create Hall Receiver "
                "connection log:",
                error
            )

    else:

        print(
            "Hall Receiver disconnected."
        )

        try:

            add_system_log(

                event_type=
                    "HALL_RECEIVER_DISCONNECTED",

                description=(
                    "Hall Receiver ESP32 disconnected."
                )
            )

        except Exception as error:

            print(
                "Unable to create Hall Receiver "
                "disconnect log:",
                error
            )


# ============================================================
# START HALL RECEIVER SERVICE
# ============================================================

def start_hall_receiver_service():
    """
    Start Hall Receiver USB communication.

    SerialService automatically detects the ESP32 serial
    port.

    No COM port is hardcoded.
    """

    global _serial_service

    # --------------------------------------------------------
    # Check system settings
    # --------------------------------------------------------

    settings = get_hall_receiver_settings()

    if not settings.get(
        "communication_enabled",
        True
    ):

        print(
            "Hall Receiver communication is disabled."
        )

        return None

    # --------------------------------------------------------
    # Prevent duplicate service
    # --------------------------------------------------------

    if _serial_service is not None:

        print(
            "Hall Receiver serial service "
            "is already running."
        )

        return _serial_service

    # --------------------------------------------------------
    # Create SerialService
    # --------------------------------------------------------

    _serial_service = SerialService(

        baud_rate=115200,

        # ----------------------------------------------------
        # Patient alerts
        # ----------------------------------------------------

        on_patient_call=(
            process_received_patient_alert
        ),

        # ----------------------------------------------------
        # General/non-alert messages
        # ----------------------------------------------------

        on_message=(
            handle_hall_receiver_message
        ),

        # ----------------------------------------------------
        # USB connection
        # ----------------------------------------------------

        on_connection_change=(
            handle_hall_receiver_connection
        ),
    )

    # --------------------------------------------------------
    # Start background communication
    # --------------------------------------------------------

    _serial_service.start()

    print(
        "Hall Receiver serial service started."
    )

    return _serial_service


# ============================================================
# STOP HALL RECEIVER SERVICE
# ============================================================

def stop_hall_receiver_service():
    """
    Stop Hall Receiver USB communication.
    """

    global _serial_service

    with _serial_lock:

        service = _serial_service

        _serial_service = None

    if service is not None:

        try:

            service.stop()

        except Exception as error:

            print(
                "Error stopping Hall Receiver service:",
                error
            )

    print(
        "Hall Receiver serial service stopped."
    )


# ============================================================
# HALL RECEIVER CONNECTION STATUS
# ============================================================

def get_hall_receiver_connection_status():
    """
    Return current Hall Receiver USB communication status.
    """

    if _serial_service is None:

        return {

            "running":
                False,

            "connected":
                False,

            "port":
                None,

            "baud_rate":
                115200,
        }

    try:

        status = _serial_service.get_status()

        if isinstance(
            status,
            dict
        ):

            return status

    except Exception as error:

        print(
            "Unable to get Hall Receiver status:",
            error
        )

    # --------------------------------------------------------
    # Safe fallback
    # --------------------------------------------------------

    return {

        "running":
            getattr(
                _serial_service,
                "running",
                False
            ),

        "connected":
            getattr(
                _serial_service,
                "connected",
                False
            ),

        "port":
            getattr(
                _serial_service,
                "port_name",
                None
            ),

        "baud_rate":
            getattr(
                _serial_service,
                "baud_rate",
                115200
            ),
    }



# ============================================================
# MAIN BACKEND ENTRY POINT
# ============================================================

def main():
    """
    Backend initialization entry point.
    """

    print(
        "=============================================="
    )

    print(APP_NAME)
    print(f"Version: {APP_VERSION}")

    print(
        "=============================================="
    )

    initialize_backend()

    if admin_exists():

        print(
            "Administrator account: CONFIGURED"
        )

        print(
            "System is ready for administrator login."
        )

    else:

        print(
            "Administrator account: NOT CONFIGURED"
        )

        print(
            "First-Time Setup is required."
        )

    print(
        "----------------------------------------------"
    )

    print(
        "Backend initialization complete."
    )

    print(
        "----------------------------------------------"
    )

#IMPORTS



# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

def run_application():
    """
    Start the local backend used by the Flutter desktop application.
    """
    import asyncio
    from backend_server import run

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        return 0

# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    initialize_backend()

    run_application()
