from __future__ import annotations
import asyncio
import sqlite3
import secrets
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from werkzeug.security import check_password_hash, generate_password_hash
from models import create_database, get_connection
from services import websocket as websocket_transport
from services.websocket import start_websocket
from services.serial_service import SerialService
from ai_assistant.assistant_service import answer_question

BASE = Path(__file__).resolve().parent
SESSIONS: dict[str, dict[str, str]] = {}
_serial_service: SerialService | None = None
logger = logging.getLogger(__name__)

KNOWLEDGE = {
    "overview": "A bedside ESP32 sends assistance events by LoRa to HALL-RECEIVER, which forwards structured events over USB to the nurse-station application. SPAEAS saves valid events with the available device assignment and updates the alert view. Angel AI is informational and does not send alerts.",
    "assistance": "The Assistance button is intended to request routine help from the nursing team. Follow your facility’s approved procedure. A button press alone does not prove that an alert was transmitted or received.",
    "emergency": "The Emergency button is intended to request urgent attention. Follow your facility’s emergency procedure. Angel AI cannot confirm delivery or response.",
    "critical": "The Critical button is intended for a critical request as defined by your facility. The project guide does not define clinical meaning or response time, so follow local protocol.",
    "cancel": "The white bedside button sends Cancel after a single press and the one-second double-press window. Two presses within one second send the patient's attended confirmation. This does not represent nurse acknowledgement.",
    "serial": "The HALL-RECEIVER forwards structured bedside events to the nurse-station application. The event is associated with the saved device location when available.",
    "websocket": "SPAEAS updates connected desktop alert views when a validated event has been saved.",
    "troubleshooting": "For technical difficulties, contact your system administrator or designated technical support. For an urgent patient need, follow the facility's emergency procedure and contact clinical staff directly.",
}

def answer(text: str) -> str:
    return answer_question(text)

def create_users_table():
    with get_connection() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS app_users (
          user_id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          recovery_key_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'USER' CHECK(role = 'USER'),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
        columns = {row["name"] for row in db.execute("PRAGMA table_info(app_users)")}
        if "recovery_key_hash" not in columns:
            db.execute("ALTER TABLE app_users ADD COLUMN recovery_key_hash TEXT NOT NULL DEFAULT ''")

def success(result): return {"ok": True, **result}

def _credential(username: str, column: str) -> str:
    if column not in {"password_hash", "recovery_key_hash"}:
        raise ValueError("Unsupported account credential.")
    with get_connection() as db:
        row = db.execute(f"SELECT {column} FROM admin WHERE username=?", (username,)).fetchone()
        if row is None:
            row = db.execute(f"SELECT {column} FROM app_users WHERE username=?", (username,)).fetchone()
    if row is None or not row[column]:
        raise PermissionError("Account credentials could not be verified.")
    return row[column]

def _account_matching_credential(column: str, credential: str) -> tuple[str, int]:
    if column not in {"password_hash", "recovery_key_hash"}:
        raise ValueError("Unsupported account credential.")
    if not credential:
        raise PermissionError("Enter the required password or recovery key.")
    with get_connection() as db:
        accounts = [
            ("admin", row["admin_id"], row[column])
            for row in db.execute(f"SELECT admin_id,{column} FROM admin").fetchall()
        ]
        accounts.extend(
            ("app_users", row["user_id"], row[column])
            for row in db.execute(f"SELECT user_id,{column} FROM app_users").fetchall()
        )
    matches = [
        (table, account_id)
        for table, account_id, stored_hash in accounts
        if stored_hash and check_password_hash(stored_hash, credential)
    ]
    if not matches:
        label = "Current password" if column == "password_hash" else "Recovery key"
        raise PermissionError(f"{label} is incorrect.")
    if len(matches) > 1:
        label = "password" if column == "password_hash" else "recovery key"
        raise PermissionError(
            f"This {label} matches more than one account. Ask an administrator to make it unique before continuing."
        )
    return matches[0]

def _session(payload: dict[str, object], *, admin: bool = False) -> dict[str, str]:
    session = SESSIONS.get(str(payload.get("token", "")))
    if session is None:
        raise PermissionError("Your session has expired. Sign in again.")
    if admin and session.get("role") != "ADMIN":
        raise PermissionError("Administrator access is required for this action.")
    return session

async def handle(_socket, request):
    action = request["action"]
    payload = request.get("payload", {})
    if action == "health":
        with get_connection() as db:
            counts = {
                "patients": db.execute("SELECT COUNT(*) FROM patients").fetchone()[0],
                "active_alerts": db.execute("SELECT COUNT(*) FROM alerts WHERE alert_status='ACTIVE'").fetchone()[0],
                "critical_alerts": db.execute("SELECT COUNT(*) FROM alerts WHERE alert_status='ACTIVE' AND upper(alert_type)='CRITICAL'").fetchone()[0],
                "emergency_alerts": db.execute("SELECT COUNT(*) FROM alerts WHERE alert_status='ACTIVE' AND upper(alert_type)='EMERGENCY'").fetchone()[0],
                "assistance_alerts": db.execute("SELECT COUNT(*) FROM alerts WHERE alert_status='ACTIVE' AND upper(alert_type)='ASSISTANCE'").fetchone()[0],
                "resolved_alerts": db.execute("SELECT COUNT(*) FROM alerts WHERE alert_status<>'ACTIVE'").fetchone()[0],
                "beds": db.execute("SELECT COUNT(*) FROM beds").fetchone()[0],
                "devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            }
            recent = [dict(row) for row in db.execute("SELECT a.id,a.alert_type,a.alert_status,a.created_at,a.bed_id,a.device_id,a.source,a.ward_id,a.patient_id,p.name AS patient_name,w.ward_type FROM alerts a LEFT JOIN patients p ON p.patient_id=a.patient_id LEFT JOIN wards w ON w.ward_id=a.ward_id ORDER BY a.id DESC LIMIT 8")]
        receiver_status = _serial_service.get_status() if _serial_service is not None else {"connected": False, "port": None}
        return success({"status":"ready", "transport":"websocket", "hardware":"unverified", "receiver_usb_connected":receiver_status["connected"], "receiver_port":receiver_status["port"], "counts":counts, "recent_alerts":recent})
    if action == "dashboard_data":
        _session(payload)
        with get_connection() as db:
            counts = {
                "patients": db.execute("SELECT COUNT(*) FROM patients").fetchone()[0],
                "active_alerts": db.execute("SELECT COUNT(*) FROM alerts WHERE alert_status='ACTIVE'").fetchone()[0],
                "beds_available": db.execute("SELECT COUNT(*) FROM beds WHERE lower(status)='available'").fetchone()[0],
                "beds_total": db.execute("SELECT COUNT(*) FROM beds").fetchone()[0],
                "devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            }
            recent = [dict(row) for row in db.execute("SELECT a.id,a.alert_type,a.alert_status,a.created_at,a.bed_id,a.device_id,a.source,a.ward_id,a.patient_id,p.name AS patient_name,w.ward_type FROM alerts a LEFT JOIN patients p ON p.patient_id=a.patient_id LEFT JOIN wards w ON w.ward_id=a.ward_id ORDER BY a.id DESC LIMIT 8")]
        receiver_status = _serial_service.get_status() if _serial_service is not None else {"connected": False, "port": None}
        return success({"counts":counts,"recent_alerts":recent,"receiver":"Connected" if receiver_status["connected"] else "Disconnected","receiver_connected":receiver_status["connected"],"receiver_port":receiver_status["port"],"hardware_verified":False})
    if action == "patients_list":
        _session(payload)
        with get_connection() as db:
            rows = db.execute("""SELECT p.patient_id AS id,p.name,p.age,p.gender,p.phone,p.notes,
                COALESCE(w.ward_type,'') AS ward,COALESCE(b.ward_id,'') AS ward_id,COALESCE(a.bed_id,'') AS bed_id
                FROM patients p LEFT JOIN patient_assignments a ON a.patient_id=p.patient_id
                LEFT JOIN beds b ON b.bed_id=a.bed_id LEFT JOIN wards w ON w.ward_id=b.ward_id
                ORDER BY p.patient_id""").fetchall()
        return success({"patients":[dict(row) for row in rows]})
    if action in ("patient_save", "patient_delete", "patient_discharge"):
        session = _session(payload)
        patient_id = str(payload.get("id", payload.get("patient_id", ""))).strip()
        if not patient_id: raise ValueError("Patient ID is required.")
        with get_connection() as db:
            existing = db.execute("SELECT patient_id FROM patients WHERE patient_id=?", (patient_id,)).fetchone()
            if action == "patient_delete":
                if existing is None: raise ValueError("Patient record was not found.")
                old = db.execute("SELECT bed_id FROM patient_assignments WHERE patient_id=?", (patient_id,)).fetchone()
                db.execute("DELETE FROM patient_assignments WHERE patient_id=?", (patient_id,))
                if old: db.execute("UPDATE beds SET status='Available' WHERE bed_id=?", (old["bed_id"],))
                db.execute("DELETE FROM patients WHERE patient_id=?", (patient_id,))
                return success({"message":"Patient record deleted."})
            if action == "patient_discharge":
                if existing is None: raise ValueError("Patient record was not found.")
                old = db.execute("SELECT bed_id FROM patient_assignments WHERE patient_id=?", (patient_id,)).fetchone()
                db.execute("DELETE FROM patient_assignments WHERE patient_id=?", (patient_id,))
                if old: db.execute("UPDATE beds SET status='Available' WHERE bed_id=?", (old["bed_id"],))
                return success({"message":"Patient discharged; the patient record was retained."})
            name = str(payload.get("name", "")).strip()
            if not name: raise ValueError("Patient name is required.")
            values = (name,str(payload.get("age", "")).strip(),str(payload.get("gender", "")).strip(),str(payload.get("phone", "")).strip(),str(payload.get("notes", "")).strip())
            if existing is None:
                db.execute("INSERT INTO patients(patient_id,name,age,gender,phone,notes) VALUES(?,?,?,?,?,?)", (patient_id,*values))
            else:
                db.execute("UPDATE patients SET name=?,age=?,gender=?,phone=?,notes=? WHERE patient_id=?", (*values,patient_id))
            ward_id = str(payload.get("ward_id", "")).strip()
            bed_id = str(payload.get("bed_id", "")).strip()
            if bool(ward_id) != bool(bed_id): raise ValueError("Choose both a ward and a bed, or leave both blank.")
            if bed_id:
                bed = db.execute("SELECT ward_id,status FROM beds WHERE bed_id=?", (bed_id,)).fetchone()
                if bed is None or bed["ward_id"] != ward_id: raise ValueError("That bed does not belong to the selected ward.")
                prior = db.execute("SELECT bed_id FROM patient_assignments WHERE patient_id=?", (patient_id,)).fetchone()
                if prior and prior["bed_id"] != bed_id:
                    db.execute("UPDATE beds SET status='Available' WHERE bed_id=?", (prior["bed_id"],))
                if db.execute("SELECT 1 FROM patient_assignments WHERE bed_id=? AND patient_id<>?", (bed_id,patient_id)).fetchone(): raise ValueError("That bed is already assigned to another patient.")
                db.execute("INSERT OR IGNORE INTO staff(staff_id) VALUES(?)", (session["username"],))
                db.execute("DELETE FROM patient_assignments WHERE patient_id=?", (patient_id,))
                db.execute("INSERT INTO patient_assignments(bed_id,patient_id,staff_id) VALUES(?,?,?)", (bed_id,patient_id,session["username"]))
                db.execute("UPDATE beds SET status='Occupied' WHERE bed_id=?", (bed_id,))
            else:
                prior = db.execute("SELECT bed_id FROM patient_assignments WHERE patient_id=?", (patient_id,)).fetchone()
                db.execute("DELETE FROM patient_assignments WHERE patient_id=?", (patient_id,))
                if prior: db.execute("UPDATE beds SET status='Available' WHERE bed_id=?", (prior["bed_id"],))
        return success({"message":"Patient record saved."})
    if action == "wards_beds_list":
        _session(payload)
        with get_connection() as db:
            wards = [dict(row) for row in db.execute("SELECT ward_id,ward_type FROM wards ORDER BY ward_id")]
            beds = [dict(row) for row in db.execute("SELECT b.bed_id,b.ward_id,b.status,w.ward_type,p.patient_id,p.name AS patient_name FROM beds b JOIN wards w ON w.ward_id=b.ward_id LEFT JOIN patient_assignments a ON a.bed_id=b.bed_id LEFT JOIN patients p ON p.patient_id=a.patient_id ORDER BY b.ward_id,b.bed_id")]
        return success({"wards":wards,"beds":beds})
    if action in ("ward_create", "ward_delete", "bed_create", "bed_delete"):
        _session(payload)
        with get_connection() as db:
            if action == "ward_create":
                ward_id=str(payload.get("ward_id", "")).strip(); ward_type=str(payload.get("ward_type", "")).strip()
                if not ward_id or not ward_type: raise ValueError("Ward ID and ward type are required.")
                try: db.execute("INSERT INTO wards(ward_id,ward_type) VALUES(?,?)",(ward_id,ward_type))
                except sqlite3.IntegrityError as error: raise ValueError("That ward ID already exists.") from error
            elif action == "ward_delete":
                ward_id=str(payload.get("ward_id", "")).strip()
                try: cursor=db.execute("DELETE FROM wards WHERE ward_id=?",(ward_id,))
                except sqlite3.IntegrityError as error: raise ValueError("Remove the ward’s beds before deleting this ward.") from error
                if cursor.rowcount == 0: raise ValueError("Ward was not found.")
            elif action == "bed_create":
                bed_id=str(payload.get("bed_id", "")).strip(); ward_id=str(payload.get("ward_id", "")).strip()
                if not bed_id or not ward_id: raise ValueError("Bed ID and ward are required.")
                try: db.execute("INSERT INTO beds(bed_id,ward_id,status) VALUES(?,?,'Available')",(bed_id,ward_id))
                except sqlite3.IntegrityError as error: raise ValueError("Check that the ward exists and the bed ID is unique.") from error
            else:
                bed_id=str(payload.get("bed_id", "")).strip()
                try:
                    cursor=db.execute("DELETE FROM beds WHERE bed_id=?",(bed_id,))
                    if cursor.rowcount == 0: raise ValueError("Bed was not found.")
                except sqlite3.IntegrityError as error: raise ValueError("Discharge or reassign the patient before deleting this bed.") from error
        return success({"message":"Beds and wards updated."})
    if action == "devices_list":
        _session(payload)
        with get_connection() as db:
            rows = db.execute("""SELECT d.device_id,d.status,d.last_seen,da.ward_id,da.bed_id,
                p.patient_id,p.name AS patient_name
                FROM devices d
                LEFT JOIN device_assignments da ON da.device_id=d.device_id
                LEFT JOIN patient_assignments pa ON pa.bed_id=da.bed_id
                LEFT JOIN patients p ON p.patient_id=pa.patient_id
                ORDER BY d.device_id""").fetchall()
        return success({"devices":[dict(row) for row in rows],"hardware":"unverified"})
    if action in ("device_create", "device_delete", "device_assign", "device_unassign"):
        _session(payload)
        device_id=str(payload.get("device_id", "")).strip()
        if not device_id: raise ValueError("Device ID is required.")
        with get_connection() as db:
            if action == "device_create":
                try: db.execute("INSERT INTO devices(device_id,status) VALUES(?,'Offline')",(device_id,))
                except sqlite3.IntegrityError as error: raise ValueError("That device ID already exists.") from error
            elif action == "device_delete":
                db.execute("DELETE FROM devices WHERE device_id=?",(device_id,))
                if db.execute("SELECT changes()").fetchone()[0] == 0: raise ValueError("Device was not found.")
            elif action == "device_assign":
                ward_id=str(payload.get("ward_id", "")).strip(); bed_id=str(payload.get("bed_id", "")).strip()
                bed=db.execute("SELECT ward_id FROM beds WHERE bed_id=?",(bed_id,)).fetchone()
                if not bed or bed["ward_id"] != ward_id: raise ValueError("Choose a bed belonging to the selected ward.")
                occupied=db.execute("SELECT device_id FROM device_assignments WHERE bed_id=? AND device_id<>?",(bed_id,device_id)).fetchone()
                if occupied: raise ValueError("That bed already has an assigned device.")
                db.execute("INSERT INTO device_assignments(device_id,ward_id,bed_id) VALUES(?,?,?) ON CONFLICT(device_id) DO UPDATE SET ward_id=excluded.ward_id,bed_id=excluded.bed_id,updated_at=CURRENT_TIMESTAMP",(device_id,ward_id,bed_id))
            else:
                cursor=db.execute("DELETE FROM device_assignments WHERE device_id=?",(device_id,))
                if cursor.rowcount == 0: raise ValueError("Device has no assignment to remove.")
        return success({"message":"Device list updated."})
    if action == "alerts_list":
        _session(payload)
        with get_connection() as db:
            rows = db.execute("SELECT a.id,a.alert_type,a.alert_status,a.created_at,a.attended_at,a.source,a.device_id,a.ward_id,a.bed_id,a.receiver_id,a.event_type,a.event_id,a.patient_id,p.name AS patient_name,w.ward_type FROM alerts a LEFT JOIN patients p ON p.patient_id=a.patient_id LEFT JOIN wards w ON w.ward_id=a.ward_id ORDER BY a.id DESC LIMIT 500").fetchall()
        return success({"alerts":[dict(row) for row in rows]})
    if action == "alert_attend":
        _session(payload)
        alert_id=payload.get("alert_id")
        with get_connection() as db:
            cursor=db.execute("UPDATE alerts SET alert_status='ATTENDED_LOCAL',attended_at=CURRENT_TIMESTAMP WHERE id=? AND alert_status='ACTIVE'",(alert_id,))
            if cursor.rowcount == 0: raise ValueError("Alert was not active or no longer exists.")
            db.execute("INSERT INTO system_logs(event_type,description) VALUES('ALERT_ACTION',?)",(f"Alert {alert_id} marked attended in the desktop application; no hardware acknowledgement was sent.",))
        return success({"message":"Alert marked attended locally. No hardware acknowledgement was sent."})
    if action == "simulate_alert":
        _session(payload)
        alert_type=str(payload.get("alert_type", "ASSISTANCE")).upper()
        if alert_type not in {"ASSISTANCE","EMERGENCY","CRITICAL"}: raise ValueError("Choose Assistance, Emergency, or Critical for a simulated alert.")
        with get_connection() as db:
            db.execute("INSERT INTO alerts(alert_type,alert_status,source) VALUES(?,'ACTIVE','SIMULATION')",(alert_type,))
            alert_id=db.execute("SELECT last_insert_rowid()").fetchone()[0]
            db.execute("INSERT INTO system_logs(event_type,description) VALUES('SIMULATION',?)",(f"Simulated {alert_type} alert #{alert_id}; no device communication occurred.",))
        return success({"alert_id":alert_id,"message":"Simulation alert created locally; no hardware message was sent."})
    if action == "logs_list":
        _session(payload)
        with get_connection() as db:
            rows=db.execute("SELECT id,event_type,description,device_id,ward_id,bed_id,patient_id,created_at FROM system_logs ORDER BY id DESC LIMIT 500").fetchall()
        return success({"logs":[dict(row) for row in rows]})
    if action == "reports_summary":
        _session(payload)
        with get_connection() as db:
            period = str(payload.get("period", "Last 7 Days"))
            ward = str(payload.get("ward", "All Wards"))
            offset_minutes = payload.get("timezone_offset_minutes", 0)
            if type(offset_minutes) is not int or not -840 <= offset_minutes <= 840:
                raise ValueError("A valid time-zone offset is required.")
            local_zone = timezone(timedelta(minutes=offset_minutes))
            now_local = datetime.now(timezone.utc).astimezone(local_zone)
            day_count = {"Last 7 Days": 7, "Last 30 Days": 30, "Last 90 Days": 90}.get(period)
            if day_count:
                first_local_day = now_local.date() - timedelta(days=day_count - 1)
            elif period == "This Year":
                first_local_day = now_local.date().replace(month=1, day=1)
            else:
                first_local_day = None

            conditions = []
            params = []
            if first_local_day is not None:
                start_local = datetime.combine(first_local_day, datetime.min.time(), tzinfo=local_zone)
                start_utc = start_local.astimezone(timezone.utc).replace(tzinfo=None)
                conditions.append("a.created_at >= ?")
                params.append(start_utc.strftime("%Y-%m-%d %H:%M:%S"))
            if ward and ward != "All Wards":
                conditions.append("w.ward_type = ?")
                params.append(ward)
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            base_query = " FROM alerts a LEFT JOIN wards w ON w.ward_id=a.ward_id" + where
            total = db.execute("SELECT COUNT(*)" + base_query, params).fetchone()[0]
            active = db.execute("SELECT COUNT(*)" + base_query + (" AND " if where else " WHERE ") + "a.alert_status='ACTIVE'", params).fetchone()[0]
            attended_local = db.execute("SELECT COUNT(*)" + base_query + (" AND " if where else " WHERE ") + "a.alert_status='ATTENDED_LOCAL'", params).fetchone()[0]
            patient_attended = db.execute("SELECT COUNT(*)" + base_query + (" AND " if where else " WHERE ") + "a.alert_status='PATIENT_CONFIRMED_ATTENDED'", params).fetchone()[0]
            cancelled = db.execute("SELECT COUNT(*)" + base_query + (" AND " if where else " WHERE ") + "a.alert_status='CANCELLED'", params).fetchone()[0]
            average_response = db.execute("SELECT AVG((julianday(a.attended_at)-julianday(a.created_at))*1440)" + base_query + (" AND " if where else " WHERE ") + "a.attended_at IS NOT NULL", params).fetchone()[0]
            types = [dict(row) for row in db.execute("SELECT a.alert_type,COUNT(*) AS count" + base_query + " GROUP BY a.alert_type ORDER BY a.alert_type", params)]
            trend_rows = db.execute("SELECT a.created_at" + base_query, params).fetchall()
            data = {
                "total_alerts": total,
                "active_alerts": active,
                "attended_alerts": attended_local,
                "patient_confirmed_attended": patient_attended,
                "cancelled_alerts": cancelled,
                "resolved_alerts": attended_local + patient_attended,
                "average_response_minutes": round(average_response, 1) if average_response is not None else None,
                "patients": db.execute("SELECT COUNT(*) FROM patients").fetchone()[0],
                "beds": db.execute("SELECT COUNT(*) FROM beds").fetchone()[0],
                "devices": db.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            }

            if period == "This Year":
                bucket_keys = [f"{now_local.year}-{month:02d}" for month in range(1, now_local.month + 1)]
                month_labels = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
                bucket_labels = [month_labels[month - 1] for month in range(1, now_local.month + 1)]
            elif first_local_day is not None:
                bucket_keys = [(first_local_day + timedelta(days=index)).isoformat() for index in range(day_count)]
                bucket_labels = [(first_local_day + timedelta(days=index)).strftime("%d %b").lstrip("0") for index in range(day_count)]
            else:
                bucket_keys = []
                bucket_labels = []
            trend_counts = {key: 0 for key in bucket_keys}
            for row in trend_rows:
                try:
                    created = datetime.fromisoformat(str(row["created_at"]))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    local_created = created.astimezone(local_zone)
                    key = local_created.strftime("%Y-%m") if period == "This Year" else local_created.date().isoformat()
                    if key in trend_counts:
                        trend_counts[key] += 1
                except (TypeError, ValueError):
                    logger.warning("Ignoring report row with invalid created_at: %r", row["created_at"])
            trend = [{"label": label, "count": trend_counts[key]} for key, label in zip(bucket_keys, bucket_labels)]
        return success({"summary": data, "alert_types": types, "trend": trend, "period": period, "ward": ward, "timezone_offset_minutes": offset_minutes, "has_data": total > 0 or data["patients"] + data["beds"] + data["devices"] > 0})
    if action == "receiver_status":
        _session(payload)
        status = _serial_service.get_status() if _serial_service is not None else {"connected": False, "port": None, "running": False}
        return success({"connected":status["connected"],"port":status["port"],"running":status["running"],"hardware":"connected" if status["connected"] else "not connected","message":"Hall receiver USB serial status."})
    if action == "setup_admin":
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        recovery = str(payload.get("recovery_key", ""))
        if not username or len(password) < 8 or not recovery:
            raise ValueError("Enter a username, a password of at least 8 characters, and a recovery key.")
        with get_connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM admin").fetchone()[0] >= 1:
                raise ValueError("An administrator account already exists. Additional administrators must be created by an authorized administrator.")
            if db.execute("SELECT 1 FROM admin WHERE username=?", (username,)).fetchone():
                raise ValueError("That username is already in use.")
            if db.execute("SELECT 1 FROM app_users WHERE username=?", (username,)).fetchone():
                raise ValueError("That username is already in use.")
            try:
                db.execute("INSERT INTO admin(username,password_hash,recovery_key_hash,role) VALUES(?,?,?,'ADMIN')", (username, generate_password_hash(password), generate_password_hash(recovery)))
            except sqlite3.IntegrityError as error:
                raise ValueError("That username is already in use.") from error
        return success({"message":"Administrator account created. Sign in to continue."})
    if action in ("create_admin", "create_user"):
        session = SESSIONS.get(str(payload.get("token", "")))
        if session is None or session.get("role") != "ADMIN":
            raise PermissionError("Administrator sign-in is required for account management.")
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        recovery = str(payload.get("recovery_key", ""))
        if not username or len(password) < 8:
            raise ValueError("Enter a username and a password of at least 8 characters.")
        if not recovery:
            raise ValueError("A recovery key is required for this account.")
        if action == "create_admin":
            recovery = str(payload.get("recovery_key", ""))
            if not recovery:
                raise ValueError("A recovery key is required for an administrator account.")
            with get_connection() as db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT COUNT(*) FROM admin").fetchone()[0] >= 2:
                    raise ValueError("Only two administrator accounts are permitted.")
                if db.execute("SELECT 1 FROM app_users WHERE username=?", (username,)).fetchone():
                    raise ValueError("That username is already in use.")
                try:
                    db.execute("INSERT INTO admin(username,password_hash,recovery_key_hash,role) VALUES(?,?,?,'ADMIN')", (username, generate_password_hash(password), generate_password_hash(recovery)))
                except sqlite3.IntegrityError as error:
                    raise ValueError("That username is already in use.") from error
            return success({"message":"Administrator account created."})
        with get_connection() as db:
            if db.execute("SELECT 1 FROM admin WHERE username=?", (username,)).fetchone():
                raise ValueError("That username is already in use.")
            try:
                db.execute("INSERT INTO app_users(username,password_hash,recovery_key_hash,role) VALUES(?,?,?,'USER')", (username, generate_password_hash(password), generate_password_hash(recovery)))
            except sqlite3.IntegrityError as error:
                raise ValueError("That username is already in use.") from error
        return success({"message":"User account created."})
    if action == "login":
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        if not username or not password: raise ValueError("Enter your username and password.")
        with get_connection() as db:
            row = db.execute("SELECT username,password_hash,role FROM admin WHERE username=?", (username,)).fetchone()
            if row is None:
                row = db.execute("SELECT username,password_hash,role FROM app_users WHERE username=?", (username,)).fetchone()
        if row is None or not check_password_hash(row["password_hash"], password):
            raise PermissionError("Username or password is incorrect.")
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = {"username":row["username"], "role":"ADMIN" if row["role"] == "ADMIN" else "USER"}
        return success({"token":token, "username":row["username"], "role":SESSIONS[token]["role"]})
    if action == "verify_admin":
        session = SESSIONS.get(str(payload.get("token", "")))
        if session is None or session.get("role") != "ADMIN":
            raise PermissionError("Sign in as an administrator before verifying credentials.")
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        with get_connection() as db:
            row = db.execute("SELECT password_hash,role FROM admin WHERE username=?", (username,)).fetchone()
        if row is None or row["role"] != "ADMIN" or not check_password_hash(row["password_hash"], password):
            raise PermissionError("Administrator username or password is incorrect.")
        return success({"verified":True})
    if action == "list_accounts":
        session = SESSIONS.get(str(payload.get("token", "")))
        if session is None or session.get("role") != "ADMIN":
            raise PermissionError("Administrator access is required to view user accounts.")
        with get_connection() as db:
            admins = db.execute("SELECT username FROM admin WHERE role='ADMIN' ORDER BY admin_id").fetchall()
            users = db.execute("SELECT username FROM app_users ORDER BY username").fetchall()
        return success({"accounts":[{"username":row["username"],"role":"Administrator"} for row in admins] + [{"username":row["username"],"role":"User"} for row in users]})
    if action in ("update_account", "delete_account"):
        session = SESSIONS.get(str(payload.get("token", "")))
        if session is None or session.get("role") != "ADMIN":
            raise PermissionError("Administrator access is required to manage accounts.")
        old_username = str(payload.get("old_username", "")).strip()
        with get_connection() as db:
            admin = db.execute("SELECT admin_id FROM admin WHERE username=?", (old_username,)).fetchone()
            user = db.execute("SELECT user_id FROM app_users WHERE username=?", (old_username,)).fetchone()
            if admin is None and user is None:
                raise ValueError("That account no longer exists. Refresh the account list.")
            if action == "delete_account":
                if admin is not None:
                    if db.execute("SELECT COUNT(*) FROM admin WHERE role='ADMIN'").fetchone()[0] <= 1:
                        raise ValueError("The last administrator account cannot be deleted.")
                    db.execute("DELETE FROM admin WHERE admin_id=?", (admin["admin_id"],))
                else:
                    db.execute("DELETE FROM app_users WHERE user_id=?", (user["user_id"],))
                return success({"message":"Account deleted."})
            new_username = str(payload.get("username", "")).strip()
            new_password = str(payload.get("password", ""))
            recovery = str(payload.get("recovery_key", ""))
            if not new_username:
                raise ValueError("Username cannot be empty.")
            if new_username != old_username:
                if db.execute("SELECT 1 FROM admin WHERE username=?", (new_username,)).fetchone() or db.execute("SELECT 1 FROM app_users WHERE username=?", (new_username,)).fetchone():
                    raise ValueError("That username is already in use.")
            if new_password and len(new_password) < 8:
                raise ValueError("New password must contain at least 8 characters.")
            assignments = ["username=?"]
            values = [new_username]
            if new_password:
                assignments.append("password_hash=?")
                values.append(generate_password_hash(new_password))
            if recovery:
                assignments.append("recovery_key_hash=?")
                values.append(generate_password_hash(recovery))
            if admin is not None:
                if str(payload.get("role", "Administrator")).casefold() != "administrator":
                    raise ValueError("Administrator accounts cannot lose administrator privileges here.")
                assignments.append("updated_at=CURRENT_TIMESTAMP")
                values.append(old_username)
                db.execute(f"UPDATE admin SET {', '.join(assignments)} WHERE username=?", values)
                role = "Administrator"
            else:
                if str(payload.get("role", "User")).casefold() == "administrator":
                    raise ValueError("Create a separate administrator account; a user account cannot be promoted.")
                values.append(old_username)
                db.execute(f"UPDATE app_users SET {', '.join(assignments)} WHERE username=?", values)
                role = "User"
        return success({"username":new_username,"role":role,"message":"Account updated."})
    if action == "reset_password_with_current":
        username = str(payload.get("username", "")).strip()
        current_password = str(payload.get("current_password", ""))
        password = str(payload.get("new_password", ""))
        if not username:
            raise ValueError("Enter your account username.")
        if len(password) < 8:
            raise ValueError("New password must contain at least 8 characters.")
        with get_connection() as db:
            row = db.execute(
                "SELECT admin_id AS account_id,password_hash,'admin' AS account_table FROM admin WHERE username=?",
                (username,),
            ).fetchone()
            if row is None:
                row = db.execute(
                    "SELECT user_id AS account_id,password_hash,'app_users' AS account_table FROM app_users WHERE username=?",
                    (username,),
                ).fetchone()
            if row is None or not check_password_hash(row["password_hash"], current_password):
                raise PermissionError("Username or current password is incorrect.")
            table = row["account_table"]
            id_column = "admin_id" if table == "admin" else "user_id"
            db.execute(
                f"UPDATE {table} SET password_hash=? WHERE {id_column}=?",
                (generate_password_hash(password), row["account_id"]),
            )
        return success({"message":"Password updated. Return to login and sign in with your new password."})
    if action == "reset_password":
        username = str(payload.get("username", "")).strip()
        recovery = str(payload.get("recovery_key", ""))
        password = str(payload.get("new_password", ""))
        if len(password) < 8: raise ValueError("New password must contain at least 8 characters.")
        if not username:
            raise ValueError("Enter your account username.")
        with get_connection() as db:
            row = db.execute("SELECT admin_id,recovery_key_hash,'admin' AS account_table FROM admin WHERE username=?", (username,)).fetchone()
            if row is None:
                row = db.execute("SELECT user_id AS admin_id,recovery_key_hash,'app_users' AS account_table FROM app_users WHERE username=?", (username,)).fetchone()
            if row is None or not row["recovery_key_hash"] or not check_password_hash(row["recovery_key_hash"], recovery):
                raise PermissionError("Username or recovery key is incorrect.")
            table, account_id = row["account_table"], row["admin_id"]
        id_column = "admin_id" if table == "admin" else "user_id"
        with get_connection() as db:
            db.execute(
                f"UPDATE {table} SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE {id_column}=?"
                if table == "admin"
                else f"UPDATE {table} SET password_hash=? WHERE {id_column}= ?",
                (generate_password_hash(password), account_id),
            )
        return success({"message":"Password updated. Return to login and sign in with your new password."})
    if action in ("change_password", "change_password_recovery", "change_recovery_key", "change_username"):
        token = str(payload.get("token", ""))
        session = SESSIONS.get(token)
        if session is None:
            raise PermissionError("Your session has expired. Sign in again.")
        username = session["username"]
        new_password = str(payload.get("new_password", ""))
        if action in ("change_password", "change_password_recovery") and len(new_password) < 8:
            raise ValueError("New password must contain at least 8 characters.")
        if action == "change_username":
            new_username = str(payload.get("new_username", "")).strip()
            current_password = str(payload.get("current_password", ""))
            if not new_username or not check_password_hash(
                _credential(username, "password_hash"), current_password
            ):
                raise PermissionError("Current password is incorrect or the new username is empty.")
            with get_connection() as db:
                if db.execute("SELECT 1 FROM admin WHERE username=?", (new_username,)).fetchone() or db.execute("SELECT 1 FROM app_users WHERE username=?", (new_username,)).fetchone():
                    raise ValueError("That username is already in use.")
                table = "admin" if session["role"] == "ADMIN" else "app_users"
                db.execute(f"UPDATE {table} SET username=? WHERE username=?", (new_username, username))
            session["username"] = new_username
            return success({"username":new_username,"message":"Username updated."})
        if action == "change_recovery_key":
            current_key = str(payload.get("current_recovery_key", ""))
            new_key = str(payload.get("new_recovery_key", ""))
            if not new_key:
                raise ValueError("Enter a new recovery key.")
            if not check_password_hash(_credential(username, "recovery_key_hash"), current_key):
                raise PermissionError("Current recovery key is incorrect.")
            with get_connection() as db:
                table = "admin" if session["role"] == "ADMIN" else "app_users"
                db.execute(f"UPDATE {table} SET recovery_key_hash=? WHERE username=?", (generate_password_hash(new_key), username))
            return success({"message":"Recovery key updated."})
        if action == "change_password":
            current_password = str(payload.get("current_password", ""))
            if not check_password_hash(_credential(username, "password_hash"), current_password):
                raise PermissionError("Current password is incorrect.")
        else:
            current_key = str(payload.get("recovery_key", ""))
            if not check_password_hash(_credential(username, "recovery_key_hash"), current_key):
                raise PermissionError("Recovery key is incorrect.")
        with get_connection() as db:
            table = "admin" if session["role"] == "ADMIN" else "app_users"
            db.execute(f"UPDATE {table} SET password_hash=? WHERE username=?", (generate_password_hash(new_password), username))
        return success({"message":"Password updated."})
    if action == "angel_ai":
        text = str(payload.get("message", "")).strip()
        if not text: raise ValueError("Enter a question for Angel AI.")
        if len(text) > 2000: raise ValueError("Please keep the question under 2,000 characters.")
        return success({"answer":answer(text), "source":"project guide", "live_status_checked":False})
    if action == "logout":
        SESSIONS.pop(str(payload.get("token", "")), None)
        return success({"message":"Signed out."})
    raise ValueError("Unknown backend action.")

def _receiver_connection_changed(connected: bool) -> None:
    service = websocket_transport.websocket_service
    if service is not None:
        service.send_from_serial({"event": "receiver.connection", "connected": connected})


def _process_receiver_message(message) -> None:
    """Validate, persist, then broadcast one HALL-RECEIVER event."""
    payload = getattr(message, "payload", {})
    if not isinstance(payload, dict):
        logger.error("Rejected receiver message without a JSON object payload")
        return
    if type(payload.get("version")) is not int or payload.get("version") != 1:
        logger.warning("Rejected receiver event with unsupported protocol version: %r", payload.get("version"))
        return
    if not all(isinstance(payload.get(key), str) for key in ("event", "device", "receiver")):
        logger.warning("Rejected receiver event with non-string identity or event fields")
        return
    event = payload["event"].strip().upper()
    category = str(payload.get("type", "")).strip().upper() if event == "ALERT" else event
    device_id = payload["device"].strip()
    receiver_id = payload["receiver"].strip()
    raw_event_id = payload.get("event_id")
    if raw_event_id is not None and (not isinstance(raw_event_id, str) or len(raw_event_id) > 128):
        logger.warning("Rejected receiver event with invalid event_id")
        return
    event_id = raw_event_id.strip() or None if isinstance(raw_event_id, str) else None
    if not device_id or receiver_id != "HALL-RECEIVER":
        logger.warning("Rejected receiver event with invalid version or identity: %r", payload)
        return
    if event == "ALERT" and category not in {"CRITICAL", "EMERGENCY", "ASSISTANCE"}:
        logger.warning("Rejected receiver alert with invalid category: %r", payload)
        return
    if event not in {"ALERT", "CANCEL", "ATTENDED"}:
        logger.warning("Rejected receiver event type: %r", event)
        return
    if event == "ATTENDED" and payload.get("source") != "PATIENT":
        logger.warning("Rejected attendance event without patient source")
        return

    try:
        with get_connection() as db:
            device = db.execute("SELECT device_id FROM devices WHERE device_id=?", (device_id,)).fetchone()
            newly_detected = device is None
            if newly_detected:
                # Learn device identifiers from authenticated receiver events;
                # assignments remain an explicit desktop-managed operation.
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", device_id):
                    logger.warning("Rejected invalid device identifier %r", device_id)
                    return
                db.execute("INSERT INTO devices(device_id,status,last_seen) VALUES(?,'Online',CURRENT_TIMESTAMP)", (device_id,))
                db.execute("INSERT INTO system_logs(event_type,description,device_id) VALUES('DEVICE_DETECTED',?,?)", (f"Device {device_id} was discovered through {receiver_id}.", device_id))
            if event_id:
                prior = db.execute("SELECT id FROM alerts WHERE event_id=?", (event_id,)).fetchone()
                if prior is not None:
                    logger.info("Ignoring duplicate receiver event %s", event_id)
                    return

            alert = None
            duplicate = False
            if event == "ALERT":
                assignment = db.execute("""SELECT da.ward_id, da.bed_id, pa.patient_id, pa.staff_id
                    FROM device_assignments da
                    LEFT JOIN patient_assignments pa ON pa.bed_id=da.bed_id
                    WHERE da.device_id=?""", (device_id,)).fetchone()
                # Firmware events without an event_id can be retransmitted, so
                # suppress only packets within a short duplicate window. An
                # older still-active alert must not hide a new button press.
                existing = db.execute("SELECT id FROM alerts WHERE device_id=? AND alert_type=? AND alert_status='ACTIVE' AND created_at >= datetime('now','-3 seconds') ORDER BY id DESC LIMIT 1", (device_id, category)).fetchone()
                if existing is not None:
                    # Repeated packets inside the window do not create a second
                    # row or live notification.
                    alert_id = existing["id"]
                    duplicate = True
                else:
                    values = tuple(assignment[key] if assignment else None for key in ("ward_id", "bed_id", "patient_id", "staff_id"))
                    cursor = db.execute("""INSERT INTO alerts(device_id,ward_id,bed_id,patient_id,staff_id,alert_type,alert_status,source,receiver_id,event_type,event_id)
                        VALUES(?,?,?,?,?,?,'ACTIVE','HARDWARE',?,'ALERT',?)""", (device_id, *values[:3], values[3], category, receiver_id, event_id))
                    alert_id = cursor.lastrowid
                db.execute("UPDATE devices SET status='Online',last_seen=CURRENT_TIMESTAMP WHERE device_id=?", (device_id,))
            else:
                target = db.execute("SELECT id FROM alerts WHERE device_id=? AND alert_status='ACTIVE' ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
                alert_id = target["id"] if target else None
                if target:
                    new_status = "CANCELLED" if event == "CANCEL" else "PATIENT_CONFIRMED_ATTENDED"
                    if event == "CANCEL":
                        db.execute("UPDATE alerts SET alert_status=?,event_type=?,receiver_id=?,event_id=? WHERE id=?", (new_status,event,receiver_id,event_id,alert_id))
                    else:
                        db.execute("UPDATE alerts SET alert_status=?,attended_at=CURRENT_TIMESTAMP,event_type=?,receiver_id=?,event_id=? WHERE id=?", (new_status,event,receiver_id,event_id,alert_id))
                db.execute("UPDATE devices SET status='Online',last_seen=CURRENT_TIMESTAMP WHERE device_id=?", (device_id,))

            if alert_id is not None:
                alert = db.execute("""SELECT a.id,a.device_id,a.ward_id,w.ward_type,a.bed_id,a.patient_id,p.name AS patient_name,
                    a.alert_type,a.alert_status,a.created_at,a.attended_at,a.source,a.receiver_id,a.event_type,a.event_id
                    FROM alerts a LEFT JOIN wards w ON w.ward_id=a.ward_id LEFT JOIN patients p ON p.patient_id=a.patient_id
                    WHERE a.id=?""", (alert_id,)).fetchone()
                db.execute("INSERT INTO system_logs(event_type,description,device_id,ward_id,bed_id,patient_id) VALUES(?,?,?,?,?,?)",
                    ("RECEIVER_EVENT", f"{event} event from {device_id} via {receiver_id}.", device_id, alert["ward_id"], alert["bed_id"], alert["patient_id"]))
            else:
                db.execute("INSERT INTO system_logs(event_type,description,device_id) VALUES('RECEIVER_EVENT',?,?)", (f"{event} event from {device_id} via {receiver_id}; no active alert was available to update.", device_id))

            broadcast = {"event": "alert.updated" if event != "ALERT" or (alert and alert["alert_status"] != "ACTIVE") else "alert.created", "data": dict(alert) if alert else {"device_id":device_id,"receiver_id":receiver_id,"event_type":event,"event_id":event_id}}
    except Exception:
        logger.exception("Failed to persist receiver event from %s", device_id)
        return

    if duplicate:
        return

    # The SQLite transaction above has committed before this thread-safe enqueue.
    service = websocket_transport.websocket_service
    if service is None:
        logger.error("Persisted receiver event could not be queued: WebSocket server is unavailable")
        return
    if newly_detected and not service.send_from_serial({"event":"device.detected","data":{"device_id":device_id,"receiver_id":receiver_id}}):
        logger.error("Detected device could not be queued for WebSocket delivery")
    if not service.send_from_serial(broadcast):
        logger.error("Persisted receiver event could not be queued for WebSocket delivery")


async def run():
    global _serial_service
    create_database()
    create_users_table()
    try:
        server_task = asyncio.create_task(start_websocket("127.0.0.1", 8765, request_handler=handle))
        for _ in range(100):
            if websocket_transport.websocket_service is not None:
                break
            if server_task.done():
                await server_task
            await asyncio.sleep(0.01)
        _serial_service = SerialService(
            port_hint=os.environ.get("SPAEAS_RECEIVER_PORT"),
            on_message=_process_receiver_message,
            on_connection_change=_receiver_connection_changed,
        )
        _serial_service.start()
        await server_task
    except OSError as error:
        if getattr(error, "winerror", None) == 10048 or error.errno == 10048:
            print("The local WebSocket backend is already using 127.0.0.1:8765. Use the running backend; close its existing terminal before starting another copy.")
            return
        raise
    finally:
        if _serial_service is not None:
            _serial_service.stop()
            _serial_service = None

if __name__ == "__main__":
    try: asyncio.run(run())
    except KeyboardInterrupt: pass
