from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
import json
import math
from pathlib import Path
import re

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.utils import logger


mylog = logger.set_log()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class Auth(BaseModel):
    login: str
    password: str
    ip: str | None = None


FAILED_WINDOW = timedelta(minutes=5)
BLOCK_DURATION = timedelta(minutes=15)
FAILED_WARNING_THRESHOLD = 3
FAILED_BLOCK_THRESHOLD = 5
MAX_EVENTS = 200
MAX_ALERTS = 50
SUSPICIOUS_HOURS = {0, 1, 2, 3, 4, 5}
SQLI_PATTERNS = [
    re.compile(r"('|%27)\s*or\s*1=1", re.IGNORECASE),
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
    re.compile(r"--"),
    re.compile(r";"),
]

event_history: list[dict] = []
admin_alerts: deque[dict] = deque(maxlen=MAX_ALERTS)
failed_attempts: dict[str, deque[datetime]] = defaultdict(deque)
blocked_ips: dict[str, datetime] = {}
known_ips_by_login: dict[str, set[str]] = defaultdict(set)
ip_counters: Counter[str] = Counter()
SECURITY_LOG_PATH = Path("security_events.log")
APP_LOG_PATH = Path("fileHand.log")


def now_local() -> datetime:
    return datetime.now().replace(microsecond=0)


def cleanup_failed_attempts(ip: str, current_time: datetime) -> None:
    attempts = failed_attempts[ip]
    while attempts and current_time - attempts[0] > FAILED_WINDOW:
        attempts.popleft()


def remove_expired_blocks(current_time: datetime) -> None:
    expired = [ip for ip, until in blocked_ips.items() if until <= current_time]
    for ip in expired:
        del blocked_ips[ip]


def detect_sql_injection(*values: str) -> bool:
    for value in values:
        for pattern in SQLI_PATTERNS:
            if pattern.search(value):
                return True
    return False


def add_alert(kind: str, message: str, ip: str, login: str, timestamp: datetime) -> None:
    alert = {
        "kind": kind,
        "message": message,
        "ip": ip,
        "login": login,
        "timestamp": timestamp.isoformat(sep=" "),
    }
    admin_alerts.appendleft(alert)
    mylog.warning("ADMIN ALERT | %s | login=%s | ip=%s | %s", kind, login, ip, message)


def append_security_log(payload: dict) -> None:
    SECURITY_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with SECURITY_LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(payload, ensure_ascii=False) + "\n")


def clear_runtime_history() -> None:
    event_history.clear()
    admin_alerts.clear()
    failed_attempts.clear()
    blocked_ips.clear()
    known_ips_by_login.clear()
    ip_counters.clear()


def clear_security_log_file() -> None:
    SECURITY_LOG_PATH.write_text("", encoding="utf-8")


def clear_app_log_file() -> None:
    APP_LOG_PATH.write_text("", encoding="utf-8")


def get_ip_activity_anomaly(ip: str) -> bool:
    counts = list(ip_counters.values())
    if len(counts) < 2:
        return False

    mean = sum(counts) / len(counts)
    variance = sum((count - mean) ** 2 for count in counts) / len(counts)
    std_dev = math.sqrt(variance)
    if std_dev == 0:
        return False

    return ip_counters[ip] >= 3 and ip_counters[ip] > mean + (2 * std_dev)


def record_event(
    *,
    timestamp: datetime,
    login: str,
    ip: str,
    status: str,
    anomalies: list[str],
    detail: str,
) -> dict:
    event = {
        "timestamp": timestamp.isoformat(sep=" "),
        "login": login,
        "ip": ip,
        "status": status,
        "anomalies": anomalies,
        "detail": detail,
    }
    event_history.append(event)
    if len(event_history) > MAX_EVENTS:
        del event_history[:-MAX_EVENTS]

    level = mylog.warning if anomalies or status != "success" else mylog.info
    anomaly_text = ", ".join(anomalies) if anomalies else "none"
    level(
        "AUTH event | status=%s | login=%s | ip=%s | anomalies=%s | detail=%s",
        status,
        login,
        ip,
        anomaly_text,
        detail,
    )
    append_security_log(event)
    return event


def build_chart(hours: int = 12) -> list[dict]:
    current_time = now_local()
    buckets = []
    bucket_index: dict[str, dict] = {}

    for offset in range(hours - 1, -1, -1):
        bucket_time = (current_time - timedelta(hours=offset)).replace(
            minute=0,
            second=0,
            microsecond=0,
        )
        label = bucket_time.strftime("%H:%M")
        bucket = {"label": label, "suspicious": 0, "blocked": 0, "sqlInjection": 0}
        buckets.append(bucket)
        bucket_index[label] = bucket

    for event in event_history:
        event_time = datetime.fromisoformat(event["timestamp"])
        label = event_time.replace(minute=0, second=0, microsecond=0).strftime("%H:%M")
        bucket = bucket_index.get(label)
        if not bucket:
            continue
        if event["status"] == "blocked":
            bucket["blocked"] += 1
        if event["status"] != "success" and event["anomalies"]:
            bucket["suspicious"] += 1
        if "sql_injection" in event["anomalies"]:
            bucket["sqlInjection"] += 1

    return buckets


def dashboard_payload() -> dict:
    remove_expired_blocks(now_local())

    suspicious_events = [event for event in event_history if event["anomalies"]]
    status_counts = Counter(event["status"] for event in event_history)

    return {
        "summary": {
            "totalEvents": len(event_history),
            "suspiciousEvents": len(suspicious_events),
            "successfulLogins": status_counts.get("success", 0),
            "failedLogins": status_counts.get("failed", 0),
            "blockedAttempts": status_counts.get("blocked", 0),
            "activeBlocks": len(blocked_ips),
        },
        "alerts": list(admin_alerts)[:8],
        "events": list(reversed(event_history[-20:])),
        "blockedIps": [
            {"ip": ip, "blockedUntil": until.isoformat(sep=" ")}
            for ip, until in sorted(blocked_ips.items(), key=lambda item: item[1], reverse=True)
        ],
        "chart": build_chart(),
    }


@app.get("/api/dashboard")
async def get_dashboard():
    return dashboard_payload()


@app.post("/api/history/clear")
async def clear_history():
    clear_runtime_history()
    clear_security_log_file()
    clear_app_log_file()
    return {
        "message": "История логов, графика и уведомлений очищена.",
        "dashboard": dashboard_payload(),
    }


@app.get("/api/logs/download")
async def download_logs():
    if not SECURITY_LOG_PATH.exists():
        SECURITY_LOG_PATH.write_text("", encoding="utf-8")
    return FileResponse(
        path=SECURITY_LOG_PATH,
        media_type="text/plain",
        filename="security_events.log",
    )


@app.post("/api/login")
async def login(auth: Auth, request: Request):
    current_time = now_local()
    remove_expired_blocks(current_time)

    login_value = auth.login.strip()
    password_value = auth.password.strip()
    ip = (auth.ip or request.client.host or "unknown").strip() or "unknown"

    anomalies: list[str] = []
    detail_parts: list[str] = []

    if ip in blocked_ips:
        blocked_until = blocked_ips[ip]
        anomalies.append("ip_blocked")
        detail = f"Вход запрещен до {blocked_until.isoformat(sep=' ')}"
        add_alert(
            "ip_blocked",
            "Обнаружена попытка входа с заблокированного IP-адреса.",
            ip,
            login_value,
            current_time,
        )
        record_event(
            timestamp=current_time,
            login=login_value,
            ip=ip,
            status="blocked",
            anomalies=anomalies,
            detail=detail,
        )
        return {
            "ok": False,
            "message": "Вход временно заблокирован из-за аномальной активности.",
            "anomalies": anomalies,
            "dashboard": dashboard_payload(),
        }

    ip_counters[ip] += 1

    if detect_sql_injection(login_value, password_value):
        anomalies.append("sql_injection")
        detail_parts.append("Обнаружен признак SQL-инъекции.")
        add_alert(
            "sql_injection",
            "Найдена подозрительная строка, похожая на SQL-инъекцию.",
            ip,
            login_value,
            current_time,
        )

    credentials_ok = login_value == "admin" and password_value == "admin"

    if credentials_ok:
        if current_time.hour in SUSPICIOUS_HOURS:
            anomalies.append("night_login")
            detail_parts.append("Вход выполнен в ночное время.")
            add_alert(
                "night_login",
                "Зафиксирован ночной вход в систему.",
                ip,
                login_value,
                current_time,
            )

        if ip not in known_ips_by_login[login_value]:
            detail_parts.append("Для пользователя замечен новый IP-адрес.")

        known_ips_by_login[login_value].add(ip)

        if get_ip_activity_anomaly(ip):
            anomalies.append("ip_activity_spike")
            detail_parts.append("IP показывает статистически необычную активность.")
            add_alert(
                "ip_activity_spike",
                "IP-адрес превысил обычный уровень активности.",
                ip,
                login_value,
                current_time,
            )

        detail = " ".join(detail_parts) or "Аутентификация прошла успешно."
        record_event(
            timestamp=current_time,
            login=login_value,
            ip=ip,
            status="success",
            anomalies=anomalies,
            detail=detail,
        )
        return {
            "ok": True,
            "message": "Аутентификация прошла успешно.",
            "anomalies": anomalies,
            "dashboard": dashboard_payload(),
        }

    failed_attempts[ip].append(current_time)
    cleanup_failed_attempts(ip, current_time)
    attempts_in_window = len(failed_attempts[ip])

    if attempts_in_window >= FAILED_WARNING_THRESHOLD:
        anomalies.append("failed_burst")
        detail_parts.append(
            f"Зафиксировано {attempts_in_window} неудачных попыток входа за короткий промежуток времени."
        )
        add_alert(
            "failed_burst",
            "Обнаружена серия неудачных попыток аутентификации.",
            ip,
            login_value,
            current_time,
        )

    if attempts_in_window >= FAILED_BLOCK_THRESHOLD:
        blocked_until = current_time + BLOCK_DURATION
        blocked_ips[ip] = blocked_until
        anomalies.append("auth_blocked")
        detail_parts.append(f"IP заблокирован до {blocked_until.isoformat(sep=' ')}.")
        add_alert(
            "auth_blocked",
            "IP-адрес заблокирован после частых неудачных попыток входа.",
            ip,
            login_value,
            current_time,
        )

    if get_ip_activity_anomaly(ip):
        anomalies.append("ip_activity_spike")
        detail_parts.append("IP показывает статистически необычную активность.")

    detail = " ".join(detail_parts) or "Неверный логин или пароль."
    record_event(
        timestamp=current_time,
        login=login_value,
        ip=ip,
        status="failed",
        anomalies=anomalies,
        detail=detail,
    )
    return {
        "ok": False,
        "message": "Аутентификация не пройдена.",
        "anomalies": anomalies,
        "dashboard": dashboard_payload(),
    }
