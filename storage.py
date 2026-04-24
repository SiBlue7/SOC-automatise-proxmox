import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from detection import AlertCandidate


def iso_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


@contextmanager
def connect_db(db_path: str):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db(db_path: str) -> None:
    with connect_db(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                node TEXT NOT NULL,
                vmid INTEGER,
                scope TEXT NOT NULL,
                status TEXT,
                cpu_percent REAL,
                ram_used_gib REAL,
                ram_total_gib REAL,
                ram_percent REAL,
                swap_used_gib REAL,
                swap_total_gib REAL,
                uptime_seconds INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_key TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                active_since TEXT NOT NULL,
                resolved_at TEXT,
                node TEXT NOT NULL,
                vmid INTEGER,
                scope TEXT NOT NULL,
                event_type TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                threshold REAL NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                node TEXT NOT NULL,
                vmid INTEGER NOT NULL,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                protected INTEGER NOT NULL DEFAULT 0,
                message TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_metrics_node_time ON metrics(node, timestamp)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status_time ON alerts(status, first_seen)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_key_status ON alerts(alert_key, status)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_actions_time ON actions(timestamp)")


def insert_host_metric(db_path: str, node: str, node_status: Dict[str, object], timestamp: datetime) -> None:
    memory = node_status.get("memory", {})
    swap = node_status.get("swap", {})
    memory_used = int(memory.get("used", 0))
    memory_total = int(memory.get("total", 0))
    swap_used = int(swap.get("used", 0))
    swap_total = int(swap.get("total", 0))
    with connect_db(db_path) as connection:
        connection.execute(
            """
            INSERT INTO metrics (
                timestamp, node, vmid, scope, status, cpu_percent,
                ram_used_gib, ram_total_gib, ram_percent,
                swap_used_gib, swap_total_gib, uptime_seconds
            )
            VALUES (?, ?, NULL, 'host', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                iso_timestamp(timestamp),
                node,
                str(node_status.get("status", "unknown")),
                round(float(node_status.get("cpu", 0.0)) * 100, 2),
                memory_used / (1024 ** 3),
                memory_total / (1024 ** 3),
                (memory_used / memory_total) * 100 if memory_total > 0 else 0.0,
                swap_used / (1024 ** 3),
                swap_total / (1024 ** 3),
                int(node_status.get("uptime", 0)),
            ),
        )


def insert_vm_metric(db_path: str, node: str, vm: Dict[str, object], timestamp: datetime) -> None:
    memory_used = int(vm.get("mem", 0))
    memory_total = int(vm.get("maxmem", 0))
    with connect_db(db_path) as connection:
        connection.execute(
            """
            INSERT INTO metrics (
                timestamp, node, vmid, scope, status, cpu_percent,
                ram_used_gib, ram_total_gib, ram_percent,
                swap_used_gib, swap_total_gib, uptime_seconds
            )
            VALUES (?, ?, ?, 'vm', ?, ?, ?, ?, ?, NULL, NULL, ?)
            """,
            (
                iso_timestamp(timestamp),
                node,
                int(vm["vmid"]),
                str(vm.get("status", "unknown")),
                round(float(vm.get("cpu", 0.0)) * 100, 2),
                memory_used / (1024 ** 3),
                memory_total / (1024 ** 3),
                (memory_used / memory_total) * 100 if memory_total > 0 else 0.0,
                int(vm.get("uptime", 0)),
            ),
        )


def upsert_alert(db_path: str, alert: AlertCandidate) -> Tuple[int, bool]:
    with connect_db(db_path) as connection:
        existing = connection.execute(
            """
            SELECT id FROM alerts
            WHERE alert_key = ? AND status = 'active'
            ORDER BY first_seen DESC
            LIMIT 1
            """,
            (alert.alert_key,),
        ).fetchone()

        if existing:
            alert_id = int(existing["id"])
            connection.execute(
                """
                UPDATE alerts
                SET last_seen = ?, value = ?, threshold = ?, severity = ?,
                    score = ?, message = ?
                WHERE id = ?
                """,
                (
                    iso_timestamp(alert.detected_at),
                    alert.value,
                    alert.threshold,
                    alert.severity,
                    alert.score,
                    alert.message,
                    alert_id,
                ),
            )
            return alert_id, False

        cursor = connection.execute(
            """
            INSERT INTO alerts (
                alert_key, first_seen, last_seen, active_since, resolved_at,
                node, vmid, scope, event_type, metric, value, threshold,
                severity, score, status, message
            )
            VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
            """,
            (
                alert.alert_key,
                iso_timestamp(alert.detected_at),
                iso_timestamp(alert.detected_at),
                iso_timestamp(alert.active_since),
                alert.node,
                alert.vmid,
                alert.scope,
                alert.event_type,
                alert.metric,
                alert.value,
                alert.threshold,
                alert.severity,
                alert.score,
                alert.message,
            ),
        )
        return int(cursor.lastrowid), True


def resolve_alerts_for_node(db_path: str, node: str, active_keys: Iterable[str], resolved_at: datetime) -> None:
    active_key_list = list(active_keys)
    with connect_db(db_path) as connection:
        if active_key_list:
            placeholders = ",".join("?" for _ in active_key_list)
            connection.execute(
                f"""
                UPDATE alerts
                SET status = 'resolved', resolved_at = ?
                WHERE node = ? AND status = 'active' AND alert_key NOT IN ({placeholders})
                """,
                (iso_timestamp(resolved_at), node, *active_key_list),
            )
        else:
            connection.execute(
                """
                UPDATE alerts
                SET status = 'resolved', resolved_at = ?
                WHERE node = ? AND status = 'active'
                """,
                (iso_timestamp(resolved_at), node),
            )


def insert_action(
    db_path: str,
    node: str,
    vmid: int,
    action: str,
    result: str,
    message: str,
    protected: bool = False,
    timestamp: Optional[datetime] = None,
) -> None:
    event_time = timestamp or datetime.now()
    with connect_db(db_path) as connection:
        connection.execute(
            """
            INSERT INTO actions (timestamp, node, vmid, action, result, protected, message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (iso_timestamp(event_time), node, vmid, action, result, int(protected), message),
        )


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> List[Dict[str, object]]:
    return [dict(row) for row in rows]


def fetch_alerts(
    db_path: str,
    limit: int = 200,
    node: Optional[str] = None,
    vmid: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, object]]:
    clauses = []
    params: List[object] = []
    if node and node != "Tous":
        clauses.append("node = ?")
        params.append(node)
    if vmid is not None:
        clauses.append("vmid = ?")
        params.append(vmid)
    if severity and severity != "Toutes":
        clauses.append("severity = ?")
        params.append(severity)
    if status and status != "Tous":
        clauses.append("status = ?")
        params.append(status)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect_db(db_path) as connection:
        rows = connection.execute(
            f"""
            SELECT id, first_seen, last_seen, resolved_at, node, vmid, scope,
                   event_type, metric, value, threshold, severity, score,
                   status, message
            FROM alerts
            {where_sql}
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 3
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 1
                    ELSE 0
                END DESC,
                first_seen DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
    return rows_to_dicts(rows)


def fetch_actions(db_path: str, limit: int = 100) -> List[Dict[str, object]]:
    with connect_db(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, timestamp, node, vmid, action, result, protected, message
            FROM actions
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return rows_to_dicts(rows)


def fetch_soc_metrics(db_path: str) -> Dict[str, object]:
    with connect_db(db_path) as connection:
        active_alerts = connection.execute(
            "SELECT COUNT(*) AS count FROM alerts WHERE status = 'active'"
        ).fetchone()["count"]
        total_alerts = connection.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"]
        total_actions = connection.execute("SELECT COUNT(*) AS count FROM actions").fetchone()["count"]
        avg_mttd = connection.execute(
            """
            SELECT AVG((julianday(first_seen) - julianday(active_since)) * 86400.0) AS value
            FROM alerts
            """
        ).fetchone()["value"]
        avg_mttr = connection.execute(
            """
            SELECT AVG(
                (
                    julianday(
                        (
                            SELECT MIN(actions.timestamp)
                            FROM actions
                            WHERE actions.result = 'success'
                              AND actions.node = alerts.node
                              AND actions.vmid = alerts.vmid
                              AND actions.timestamp >= alerts.first_seen
                        )
                    ) - julianday(alerts.first_seen)
                ) * 86400.0
            ) AS value
            FROM alerts
            WHERE alerts.vmid IS NOT NULL
            """
        ).fetchone()["value"]

    return {
        "active_alerts": int(active_alerts or 0),
        "total_alerts": int(total_alerts or 0),
        "total_actions": int(total_actions or 0),
        "avg_mttd": float(avg_mttd or 0.0),
        "avg_mttr": float(avg_mttr or 0.0),
    }
