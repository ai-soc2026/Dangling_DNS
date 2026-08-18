from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    func,
    inspect,
    insert,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.engine import Engine, make_url


DEFAULT_DATABASE_PATH = Path(__file__).resolve().with_name("danglescan.db")
DATABASE_PATH = Path(os.getenv("DANGLESCAN_DB_PATH", str(DEFAULT_DATABASE_PATH))).expanduser()
_WRITE_LOCK = threading.Lock()


def _normalise_database_url(value: str) -> str:
    if value.startswith("postgres://"):
        return value.replace("postgres://", "postgresql+psycopg://", 1)
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+psycopg://", 1)
    return value


DATABASE_URL = _normalise_database_url(
    os.getenv("DATABASE_URL", f"sqlite:///{DATABASE_PATH}")
)


def _create_engine() -> Engine:
    options: dict[str, Any] = {"pool_pre_ping": True, "future": True}
    if DATABASE_URL.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False, "timeout": 30}
    return create_engine(DATABASE_URL, **options)


engine = _create_engine()


if engine.dialect.name == "sqlite":
    @event.listens_for(engine, "connect")
    def _configure_sqlite(connection, _connection_record) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA busy_timeout = 30000")
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.close()


metadata = MetaData()

scans_table = Table(
    "scans",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("input_type", String(20), nullable=False),
    Column("input_value", Text, nullable=False),
    Column("source_domains_json", Text, nullable=False, default="[]"),
    Column("use_ai", Boolean, nullable=False, default=False),
    Column("use_enum", Boolean, nullable=False, default=False),
    Column("status", String(20), nullable=False, default="running"),
    Column("started_at", String(40), nullable=False),
    Column("completed_at", String(40)),
    Column("input_total", Integer, nullable=False, default=0),
    Column("discovered_count", Integer, nullable=False, default=0),
    Column("total_count", Integer, nullable=False, default=0),
    Column("completed_count", Integer, nullable=False, default=0),
    Column("critical_count", Integer, nullable=False, default=0),
    Column("high_count", Integer, nullable=False, default=0),
    Column("medium_count", Integer, nullable=False, default=0),
    Column("info_count", Integer, nullable=False, default=0),
    Column("inactive_count", Integer, nullable=False, default=0),
    Column("clean_count", Integer, nullable=False, default=0),
    Column("error", Text),
    CheckConstraint("input_type IN ('domain', 'excel')", name="ck_scans_input_type"),
    CheckConstraint(
        "status IN ('running', 'completed', 'stopped', 'failed')",
        name="ck_scans_status",
    ),
)

scan_results_table = Table(
    "scan_results",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("scan_id", String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
    Column("domain", Text, nullable=False),
    Column("verdict", String(50), nullable=False),
    Column("severity", String(20), nullable=False),
    Column("reason", Text),
    Column("confidence", Integer, nullable=False, default=0),
    Column("provider", Text),
    Column("provider_evidence", Text),
    Column("cname", Text),
    Column("a_records_json", Text, nullable=False, default="[]"),
    Column("aaaa_records_json", Text, nullable=False, default="[]"),
    Column("dns_resolves", Boolean, nullable=False, default=False),
    Column("dns_nxdomain", Boolean, nullable=False, default=False),
    Column("cname_target_nxdomain", Boolean, nullable=False, default=False),
    Column("dns_resolution_status", Text),
    Column("dns_query_errors_json", Text, nullable=False, default="{}"),
    Column("http_attempted", Boolean, nullable=False, default=False),
    Column("http_status", Integer),
    Column("http_title", Text),
    Column("http_url", Text),
    Column("http_error", Text),
    Column("ai_analysis", Text),
    Column("scan_time_s", Float),
    Column("evidence_json", Text, nullable=False),
    Column("remediation_status", String(30), nullable=False, default="Open"),
    Column("assigned_owner", Text),
    Column("analyst_comment", Text),
    Column("remediation_updated_at", String(40)),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "remediation_status IN ('Open', 'Investigating', 'False Positive', 'Resolved')",
        name="ck_results_remediation_status",
    ),
    UniqueConstraint("scan_id", "domain", name="uq_scan_results_scan_domain"),
)

Index("idx_scans_started_at", scans_table.c.started_at.desc())
Index("idx_scans_status", scans_table.c.status)
Index("idx_scan_results_scan_id", scan_results_table.c.scan_id)
Index("idx_scan_results_domain", scan_results_table.c.domain)
Index("idx_scan_results_verdict", scan_results_table.c.verdict)
Index("idx_scan_results_severity", scan_results_table.c.severity)
Index("idx_scan_results_provider", scan_results_table.c.provider)
Index("idx_scan_results_remediation", scan_results_table.c.remediation_status)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def initialize_database() -> None:
    metadata.create_all(engine)
    existing_columns = {
        column["name"] for column in inspect(engine).get_columns("scans")
    }
    if "info_count" not in existing_columns:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE scans ADD COLUMN info_count "
                    "INTEGER NOT NULL DEFAULT 0"
                )
            )


def create_scan(
    *,
    input_type: str,
    input_value: str,
    source_domains: list[str],
    use_ai: bool,
    use_enum: bool,
) -> str:
    scan_id = str(uuid.uuid4())
    values = {
        "id": scan_id,
        "input_type": input_type,
        "input_value": input_value,
        "source_domains_json": json.dumps(source_domains),
        "use_ai": bool(use_ai),
        "use_enum": bool(use_enum),
        "status": "running",
        "started_at": _utc_now(),
        "input_total": len(source_domains),
        "discovered_count": 0,
        "total_count": 0,
        "completed_count": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "info_count": 0,
        "inactive_count": 0,
        "clean_count": 0,
    }
    with _WRITE_LOCK, engine.begin() as connection:
        connection.execute(insert(scans_table).values(**values))
    return scan_id


def update_scan_totals(
    scan_id: str,
    *,
    total_count: Optional[int] = None,
    discovered_count: Optional[int] = None,
    completed_count: Optional[int] = None,
) -> None:
    values: dict[str, int] = {}
    for column, value in (
        ("total_count", total_count),
        ("discovered_count", discovered_count),
        ("completed_count", completed_count),
    ):
        if value is not None:
            values[column] = max(0, int(value))
    if not values:
        return
    with _WRITE_LOCK, engine.begin() as connection:
        connection.execute(
            update(scans_table).where(scans_table.c.id == scan_id).values(**values)
        )


def _result_bucket(result: dict[str, Any]) -> str:
    severity = str(result.get("severity") or "").lower()
    verdict = str(result.get("verdict") or "").lower()
    if severity in {"critical", "high", "medium"}:
        return severity
    if verdict == "inactive":
        return "inactive"
    if verdict == "clean":
        return "clean"
    return "info"


def save_scan_result(
    scan_id: str,
    result: dict[str, Any],
    *,
    completed_count: int,
    total_count: int,
) -> int:
    dns = result.get("dns") or {}
    http = result.get("http") or {}
    bucket = _result_bucket(result)
    values = {
        "scan_id": scan_id,
        "domain": result["domain"],
        "verdict": result.get("verdict") or "clean",
        "severity": result.get("severity") or "info",
        "reason": result.get("reason"),
        "confidence": int(result.get("confidence") or 0),
        "provider": result.get("provider"),
        "provider_evidence": result.get("provider_evidence"),
        "cname": dns.get("cname"),
        "a_records_json": json.dumps(dns.get("a_records") or []),
        "aaaa_records_json": json.dumps(dns.get("aaaa_records") or []),
        "dns_resolves": bool(dns.get("resolves")),
        "dns_nxdomain": bool(dns.get("nxdomain")),
        "cname_target_nxdomain": bool(dns.get("cname_target_nxdomain")),
        "dns_resolution_status": dns.get("resolution_status"),
        "dns_query_errors_json": json.dumps(dns.get("query_errors") or {}),
        "http_attempted": bool(http.get("attempted")),
        "http_status": http.get("status"),
        "http_title": http.get("title"),
        "http_url": http.get("url"),
        "http_error": http.get("error"),
        "ai_analysis": result.get("ai_analysis"),
        "scan_time_s": result.get("scan_time_s"),
        "evidence_json": json.dumps(result),
        "created_at": _utc_now(),
        "remediation_status": "Open",
    }

    with _WRITE_LOCK, engine.begin() as connection:
        existing_id = connection.execute(
            select(scan_results_table.c.id).where(
                scan_results_table.c.scan_id == scan_id,
                scan_results_table.c.domain == result["domain"],
            )
        ).scalar_one_or_none()

        if existing_id is None:
            insert_result = connection.execute(insert(scan_results_table).values(**values))
            result_id = int(insert_result.inserted_primary_key[0])
            bucket_column = getattr(scans_table.c, f"{bucket}_count")
            connection.execute(
                update(scans_table)
                .where(scans_table.c.id == scan_id)
                .values({bucket_column.key: bucket_column + 1})
            )
        else:
            result_id = int(existing_id)

        current_total = connection.execute(
            select(scans_table.c.total_count).where(scans_table.c.id == scan_id)
        ).scalar_one_or_none() or 0
        connection.execute(
            update(scans_table)
            .where(scans_table.c.id == scan_id)
            .values(
                completed_count=max(0, int(completed_count)),
                total_count=max(int(current_total), max(0, int(total_count))),
            )
        )
    return result_id


def finish_scan(
    scan_id: str,
    *,
    status: str,
    completed_count: Optional[int] = None,
    total_count: Optional[int] = None,
    discovered_count: Optional[int] = None,
    error: Optional[str] = None,
) -> None:
    if status not in {"completed", "stopped", "failed"}:
        raise ValueError("Invalid terminal scan status")
    values: dict[str, Any] = {
        "status": status,
        "completed_at": _utc_now(),
        "error": error,
    }
    for column, value in (
        ("completed_count", completed_count),
        ("total_count", total_count),
        ("discovered_count", discovered_count),
    ):
        if value is not None:
            values[column] = max(0, int(value))
    with _WRITE_LOCK, engine.begin() as connection:
        connection.execute(
            update(scans_table).where(scans_table.c.id == scan_id).values(**values)
        )


def stop_scan_if_running(scan_id: str) -> None:
    with _WRITE_LOCK, engine.begin() as connection:
        connection.execute(
            update(scans_table)
            .where(scans_table.c.id == scan_id, scans_table.c.status == "running")
            .values(status="stopped", completed_at=_utc_now())
        )


def _decode_json(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _scan_from_mapping(mapping: Any) -> dict[str, Any]:
    item = dict(mapping)
    item["source_domains"] = _decode_json(item.pop("source_domains_json", "[]"), [])
    item["use_ai"] = bool(item["use_ai"])
    item["use_enum"] = bool(item["use_enum"])
    return item


def _result_from_mapping(mapping: Any, include_evidence: bool = False) -> dict[str, Any]:
    item = dict(mapping)
    item["a_records"] = _decode_json(item.pop("a_records_json", "[]"), [])
    item["aaaa_records"] = _decode_json(item.pop("aaaa_records_json", "[]"), [])
    item["dns_query_errors"] = _decode_json(item.pop("dns_query_errors_json", "{}"), {})
    item["dns_resolves"] = bool(item["dns_resolves"])
    item["dns_nxdomain"] = bool(item["dns_nxdomain"])
    item["cname_target_nxdomain"] = bool(item["cname_target_nxdomain"])
    item["http_attempted"] = bool(item["http_attempted"])
    evidence_json = item.pop("evidence_json", "{}")
    if include_evidence:
        item["evidence"] = _decode_json(evidence_json, {})
    return item


def list_scans(
    *,
    query: str = "",
    status: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    conditions = []
    if query:
        like = f"%{query.strip()}%"
        conditions.append(or_(
            scans_table.c.input_value.ilike(like),
            scans_table.c.source_domains_json.ilike(like),
        ))
    if status:
        conditions.append(scans_table.c.status == status)
    statement = select(scans_table)
    count_statement = select(func.count()).select_from(scans_table)
    if conditions:
        statement = statement.where(*conditions)
        count_statement = count_statement.where(*conditions)
    statement = statement.order_by(scans_table.c.started_at.desc()).limit(limit).offset(offset)
    with engine.connect() as connection:
        total = int(connection.execute(count_statement).scalar_one())
        rows = connection.execute(statement).mappings().all()
    return {"total": total, "items": [_scan_from_mapping(row) for row in rows]}


def get_scan(scan_id: str) -> Optional[dict[str, Any]]:
    with engine.connect() as connection:
        row = connection.execute(
            select(scans_table).where(scans_table.c.id == scan_id)
        ).mappings().one_or_none()
    return _scan_from_mapping(row) if row else None


def list_scan_results(
    scan_id: str,
    *,
    query: str = "",
    verdict: str = "",
    severity: str = "",
    remediation_status: str = "",
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    conditions = [scan_results_table.c.scan_id == scan_id]
    if query:
        like = f"%{query.strip()}%"
        conditions.append(or_(
            scan_results_table.c.domain.ilike(like),
            scan_results_table.c.cname.ilike(like),
            scan_results_table.c.provider.ilike(like),
            scan_results_table.c.reason.ilike(like),
            scan_results_table.c.http_title.ilike(like),
        ))
    if verdict:
        conditions.append(scan_results_table.c.verdict == verdict)
    if severity:
        conditions.append(scan_results_table.c.severity == severity)
    if remediation_status:
        conditions.append(scan_results_table.c.remediation_status == remediation_status)
    statement = (
        select(scan_results_table)
        .where(*conditions)
        .order_by(scan_results_table.c.id.desc())
        .limit(limit)
        .offset(offset)
    )
    count_statement = (
        select(func.count()).select_from(scan_results_table).where(*conditions)
    )
    with engine.connect() as connection:
        total = int(connection.execute(count_statement).scalar_one())
        rows = connection.execute(statement).mappings().all()
    return {"total": total, "items": [_result_from_mapping(row) for row in rows]}


def search_results(
    *,
    query: str,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    like = f"%{query.strip()}%"
    condition = or_(
        scan_results_table.c.domain.ilike(like),
        scan_results_table.c.cname.ilike(like),
        scan_results_table.c.provider.ilike(like),
        scan_results_table.c.reason.ilike(like),
        scan_results_table.c.http_title.ilike(like),
        scan_results_table.c.http_error.ilike(like),
    )
    joined = scan_results_table.join(scans_table, scans_table.c.id == scan_results_table.c.scan_id)
    statement = (
        select(
            scan_results_table,
            scans_table.c.input_value,
            scans_table.c.started_at.label("scan_started_at"),
        )
        .select_from(joined)
        .where(condition)
        .order_by(scan_results_table.c.id.desc())
        .limit(limit)
        .offset(offset)
    )
    count_statement = select(func.count()).select_from(joined).where(condition)
    with engine.connect() as connection:
        total = int(connection.execute(count_statement).scalar_one())
        rows = connection.execute(statement).mappings().all()
    return {"total": total, "items": [_result_from_mapping(row) for row in rows]}


def get_result(result_id: int) -> Optional[dict[str, Any]]:
    joined = scan_results_table.join(scans_table, scans_table.c.id == scan_results_table.c.scan_id)
    statement = (
        select(
            scan_results_table,
            scans_table.c.input_value,
            scans_table.c.started_at.label("scan_started_at"),
        )
        .select_from(joined)
        .where(scan_results_table.c.id == result_id)
    )
    with engine.connect() as connection:
        row = connection.execute(statement).mappings().one_or_none()
    return _result_from_mapping(row, include_evidence=True) if row else None


def get_latest_result_for_domain(
    domain: str,
    *,
    exclude_scan_id: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Return the newest stored observation for a domain before the current scan."""
    conditions = [func.lower(scan_results_table.c.domain) == domain.strip().lower()]
    if exclude_scan_id:
        conditions.append(scan_results_table.c.scan_id != exclude_scan_id)
    statement = (
        select(scan_results_table)
        .where(*conditions)
        .order_by(scan_results_table.c.id.desc())
        .limit(1)
    )
    with engine.connect() as connection:
        row = connection.execute(statement).mappings().one_or_none()
    return _result_from_mapping(row, include_evidence=True) if row else None


def update_remediation(
    result_id: int,
    *,
    status: str,
    assigned_owner: Optional[str],
    analyst_comment: Optional[str],
) -> Optional[dict[str, Any]]:
    with _WRITE_LOCK, engine.begin() as connection:
        result = connection.execute(
            update(scan_results_table)
            .where(scan_results_table.c.id == result_id)
            .values(
                remediation_status=status,
                assigned_owner=assigned_owner,
                analyst_comment=analyst_comment,
                remediation_updated_at=_utc_now(),
            )
        )
        if result.rowcount == 0:
            return None
    return get_result(result_id)


def database_health() -> dict[str, Any]:
    with engine.connect() as connection:
        connection.execute(select(1)).scalar_one()
    url = make_url(DATABASE_URL)
    if engine.dialect.name == "sqlite":
        database_name = Path(url.database or str(DATABASE_PATH)).name
    else:
        database_name = url.database or "postgres"
    return {
        "enabled": True,
        "backend": engine.dialect.name,
        "database": database_name,
        "path": str(DATABASE_PATH) if engine.dialect.name == "sqlite" else None,
    }
