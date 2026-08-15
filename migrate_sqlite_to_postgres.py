from __future__ import annotations

import argparse
import os
from pathlib import Path

from sqlalchemy import create_engine, func, insert, select, text
from sqlalchemy.engine import make_url

from database import metadata, scan_results_table, scans_table


def normalise_postgres_url(value: str) -> str:
    if value.startswith("postgres://"):
        return value.replace("postgres://", "postgresql+psycopg://", 1)
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+psycopg://", 1)
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Copy DangleScan scan history from SQLite to an empty PostgreSQL database."
    )
    parser.add_argument(
        "--source",
        default=str(Path(__file__).resolve().with_name("danglescan.db")),
        help="Path to the source SQLite database.",
    )
    parser.add_argument(
        "--target-url",
        default=os.getenv("POSTGRES_DATABASE_URL", ""),
        help="PostgreSQL URL. Prefer the POSTGRES_DATABASE_URL environment variable.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and count source rows without connecting to PostgreSQL.",
    )
    return parser.parse_args()


def load_source_rows(source_path: Path) -> tuple[list[dict], list[dict]]:
    if not source_path.is_file():
        raise SystemExit(f"SQLite source does not exist: {source_path}")
    source_engine = create_engine(f"sqlite:///{source_path}", future=True)
    with source_engine.connect() as connection:
        scans = [dict(row) for row in connection.execute(select(scans_table)).mappings()]
        results = [
            dict(row)
            for row in connection.execute(select(scan_results_table)).mappings()
        ]
    source_engine.dispose()
    return scans, results


def migrate(source_path: Path, target_url: str, dry_run: bool = False) -> None:
    target_url = normalise_postgres_url(target_url)
    if not target_url:
        raise SystemExit(
            "Set POSTGRES_DATABASE_URL or pass --target-url with a PostgreSQL connection URL."
        )
    parsed_target = make_url(target_url)
    if parsed_target.get_backend_name() != "postgresql":
        raise SystemExit("The target URL must use PostgreSQL.")

    scans, results = load_source_rows(source_path)
    print(f"Source SQLite database: {source_path}")
    print(f"Scans ready to copy: {len(scans)}")
    print(f"Results ready to copy: {len(results)}")
    print(f"Target: {parsed_target.render_as_string(hide_password=True)}")

    if dry_run:
        print("Dry run complete. PostgreSQL was not changed.")
        return

    target_engine = create_engine(target_url, pool_pre_ping=True, future=True)
    metadata.create_all(target_engine)
    with target_engine.begin() as connection:
        existing_scans = int(
            connection.execute(select(func.count()).select_from(scans_table)).scalar_one()
        )
        existing_results = int(
            connection.execute(
                select(func.count()).select_from(scan_results_table)
            ).scalar_one()
        )
        if existing_scans or existing_results:
            raise SystemExit(
                "Target PostgreSQL tables are not empty. Migration stopped to prevent duplicates."
            )
        if scans:
            connection.execute(insert(scans_table), scans)
        if results:
            connection.execute(insert(scan_results_table), results)
        connection.execute(text(
            """
            SELECT setval(
                pg_get_serial_sequence('scan_results', 'id'),
                COALESCE((SELECT MAX(id) FROM scan_results), 1),
                EXISTS(SELECT 1 FROM scan_results)
            )
            """
        ))

    with target_engine.connect() as connection:
        copied_scans = int(
            connection.execute(select(func.count()).select_from(scans_table)).scalar_one()
        )
        copied_results = int(
            connection.execute(
                select(func.count()).select_from(scan_results_table)
            ).scalar_one()
        )
    target_engine.dispose()

    if copied_scans != len(scans) or copied_results != len(results):
        raise SystemExit(
            "Migration count verification failed. Keep using the SQLite database until reviewed."
        )
    print(f"Migration complete: {copied_scans} scans and {copied_results} results copied.")


if __name__ == "__main__":
    arguments = parse_args()
    migrate(Path(arguments.source).expanduser().resolve(), arguments.target_url, arguments.dry_run)
