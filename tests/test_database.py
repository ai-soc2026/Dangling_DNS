from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest

import httpx


_TEMP_DIRECTORY = tempfile.TemporaryDirectory()
os.environ.pop("DATABASE_URL", None)
os.environ["DANGLESCAN_DB_PATH"] = os.path.join(_TEMP_DIRECTORY.name, "test.db")

import database as db  # noqa: E402
import main  # noqa: E402


def sample_result(
    domain: str = "app.example.com",
    verdict: str = "dangling_dns",
    severity: str = "high",
) -> dict:
    return {
        "domain": domain,
        "verdict": verdict,
        "severity": severity,
        "provider": None,
        "provider_evidence": "CNAME does not match a known provider",
        "reason": "CNAME target returns NXDOMAIN",
        "confidence": 85,
        "ai_analysis": None,
        "dns": {
            "resolves": False,
            "nxdomain": False,
            "cname": "missing.vendor.example",
            "cname_target_nxdomain": True,
            "a_records": [],
            "aaaa_records": [],
            "record_types": ["CNAME"],
            "resolution_status": "CNAME target NXDOMAIN",
            "query_errors": {},
        },
        "http": {
            "attempted": False,
            "status": None,
            "title": None,
            "url": None,
            "error": "Not attempted",
        },
        "scan_time_s": 0.02,
    }


def healthy_result(domain: str) -> dict:
    result = sample_result(domain, verdict="clean", severity="info")
    result.update({
        "reason": "No issues detected",
        "confidence": 0,
    })
    result["dns"].update({
        "resolves": True,
        "cname_target_nxdomain": False,
        "a_records": ["192.0.2.10"],
        "record_types": ["CNAME", "A"],
        "resolution_status": "Resolved",
    })
    result["http"].update({
        "attempted": True,
        "status": 200,
        "title": "Unexpected live site",
        "url": f"https://{domain}",
        "error": None,
    })
    return result


class DatabaseTests(unittest.TestCase):
    def test_info_result_uses_info_count_not_clean_count(self) -> None:
        scan_id = db.create_scan(
            input_type="domain",
            input_value="broken.example.com",
            source_domains=["broken.example.com"],
            use_ai=False,
            use_enum=False,
        )
        result = sample_result(
            "broken.example.com",
            verdict="http_observation",
            severity="info",
        )
        result["reason"] = "HTTP 404 response requires manual validation"
        db.save_scan_result(
            scan_id,
            result,
            completed_count=1,
            total_count=1,
        )

        scan = db.get_scan(scan_id)
        self.assertEqual(scan["info_count"], 1)
        self.assertEqual(scan["clean_count"], 0)
        self.assertEqual(scan["inactive_count"], 0)

    def test_resolved_previous_finding_does_not_trigger_historical_alert(self) -> None:
        previous_evidence = sample_result("resolved-transition.example.com")
        previous = {
            "id": 999,
            "scan_id": "previous-scan",
            "verdict": "dangling_dns",
            "severity": "high",
            "remediation_status": "Resolved",
            "evidence": previous_evidence,
        }
        current = healthy_result("resolved-transition.example.com")

        evaluated = main.apply_historical_change_detection(current, previous)

        self.assertEqual(evaluated["verdict"], "clean")
        self.assertNotIn("history_evidence", evaluated)

    def test_crud_search_and_remediation(self) -> None:
        scan_id = db.create_scan(
            input_type="domain",
            input_value="example.com",
            source_domains=["example.com"],
            use_ai=False,
            use_enum=True,
        )
        result_id = db.save_scan_result(
            scan_id,
            sample_result(),
            completed_count=1,
            total_count=1,
        )
        db.finish_scan(
            scan_id,
            status="completed",
            completed_count=1,
            total_count=1,
            discovered_count=0,
        )

        scan = db.get_scan(scan_id)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["high_count"], 1)
        self.assertEqual(db.list_scan_results(scan_id, query="vendor")["total"], 1)
        self.assertEqual(db.search_results(query="NXDOMAIN")["total"], 1)
        self.assertEqual(db.get_result(result_id)["evidence"]["domain"], "app.example.com")
        latest = db.get_latest_result_for_domain("APP.EXAMPLE.COM")
        self.assertEqual(latest["id"], result_id)
        self.assertEqual(latest["evidence"]["verdict"], "dangling_dns")

        updated = db.update_remediation(
            result_id,
            status="Resolved",
            assigned_owner="DNS team",
            analyst_comment="Stale record removed",
        )
        self.assertEqual(updated["remediation_status"], "Resolved")
        self.assertEqual(updated["assigned_owner"], "DNS team")


class PersistenceStreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_unresolved_dangling_target_becoming_live_requires_ownership_validation(self) -> None:
        domain = "transition.example.com"
        previous_scan_id = db.create_scan(
            input_type="domain",
            input_value=domain,
            source_domains=[domain],
            use_ai=False,
            use_enum=False,
        )
        previous_result_id = db.save_scan_result(
            previous_scan_id,
            sample_result(domain),
            completed_count=1,
            total_count=1,
        )
        db.finish_scan(
            previous_scan_id,
            status="completed",
            completed_count=1,
            total_count=1,
            discovered_count=0,
        )

        current_scan_id = db.create_scan(
            input_type="domain",
            input_value=domain,
            source_domains=[domain],
            use_ai=False,
            use_enum=False,
        )

        async def fake_stream(domains, use_ai, use_enum):
            yield "data: " + json.dumps({
                "type": "result", "completed": 1, "total": 1,
                "result": healthy_result(domain),
            }) + "\n\n"
            yield "data: " + json.dumps({
                "type": "done", "completed": 1, "total": 1,
                "discovered": 0,
            }) + "\n\n"

        original_stream = main.stream_scan
        main.stream_scan = fake_stream
        try:
            events = [
                event async for event in main.persisted_stream_scan(
                    current_scan_id, [domain], False, False
                )
            ]
        finally:
            main.stream_scan = original_stream

        result_event = json.loads(events[0][6:])
        result = result_event["result"]
        self.assertEqual(result["verdict"], "ownership_validation_required")
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["confidence"], 80)
        self.assertEqual(
            result["history_evidence"]["previous_result_id"],
            previous_result_id,
        )
        stored = db.list_scan_results(current_scan_id)["items"][0]
        self.assertEqual(stored["verdict"], "ownership_validation_required")

    async def test_stream_saves_progressive_result_and_completion(self) -> None:
        scan_id = db.create_scan(
            input_type="domain",
            input_value="stream.example.com",
            source_domains=["stream.example.com"],
            use_ai=False,
            use_enum=False,
        )

        async def fake_stream(domains, use_ai, use_enum):
            yield "data: " + json.dumps({
                "type": "start", "total": 1, "input_total": 1,
                "discovered": 0, "enumerating": False,
            }) + "\n\n"
            yield "data: " + json.dumps({
                "type": "result", "completed": 1, "total": 1,
                "result": sample_result("stream.example.com"),
            }) + "\n\n"
            yield "data: " + json.dumps({
                "type": "done", "completed": 1, "total": 1,
                "discovered": 0,
            }) + "\n\n"

        original_stream = main.stream_scan
        main.stream_scan = fake_stream
        try:
            events = [
                event async for event in main.persisted_stream_scan(
                    scan_id, ["stream.example.com"], False, False
                )
            ]
        finally:
            main.stream_scan = original_stream

        self.assertEqual(len(events), 3)
        self.assertTrue(all(scan_id in event for event in events))
        scan = db.get_scan(scan_id)
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["completed_count"], 1)
        self.assertEqual(scan["high_count"], 1)

    async def test_closed_stream_keeps_result_and_marks_scan_stopped(self) -> None:
        scan_id = db.create_scan(
            input_type="domain",
            input_value="stopped.example.com",
            source_domains=["stopped.example.com"],
            use_ai=False,
            use_enum=False,
        )

        async def fake_stream(domains, use_ai, use_enum):
            yield "data: " + json.dumps({
                "type": "result", "completed": 1, "total": 2,
                "result": sample_result("first.stopped.example.com"),
            }) + "\n\n"
            await asyncio.sleep(60)

        original_stream = main.stream_scan
        main.stream_scan = fake_stream
        generator = main.persisted_stream_scan(
            scan_id, ["stopped.example.com"], False, False
        )
        try:
            await generator.__anext__()
            await generator.aclose()
        finally:
            main.stream_scan = original_stream

        scan = db.get_scan(scan_id)
        self.assertEqual(scan["status"], "stopped")
        self.assertEqual(scan["completed_count"], 1)
        self.assertEqual(db.list_scan_results(scan_id)["total"], 1)


class HistoryApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_history_search_detail_and_update_endpoints(self) -> None:
        scan_id = db.create_scan(
            input_type="domain",
            input_value="api.example.com",
            source_domains=["api.example.com"],
            use_ai=False,
            use_enum=True,
        )
        result_id = db.save_scan_result(
            scan_id,
            sample_result("history.api.example.com"),
            completed_count=1,
            total_count=1,
        )
        db.finish_scan(
            scan_id,
            status="completed",
            completed_count=1,
            total_count=1,
            discovered_count=0,
        )

        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            scans_response = await client.get("/history/scans", params={"q": "api.example"})
            self.assertEqual(scans_response.status_code, 200)
            self.assertGreaterEqual(scans_response.json()["total"], 1)

            results_response = await client.get(
                f"/history/scans/{scan_id}/results",
                params={"q": "history.api"},
            )
            self.assertEqual(results_response.status_code, 200)
            self.assertEqual(results_response.json()["total"], 1)

            search_response = await client.get(
                "/history/search", params={"q": "history.api.example.com"}
            )
            self.assertEqual(search_response.status_code, 200)
            self.assertGreaterEqual(search_response.json()["total"], 1)

            detail_response = await client.get(f"/history/results/{result_id}")
            self.assertEqual(detail_response.status_code, 200)
            self.assertEqual(detail_response.json()["domain"], "history.api.example.com")

            update_response = await client.patch(
                f"/history/results/{result_id}",
                json={
                    "status": "Investigating",
                    "assigned_owner": "Infrastructure",
                    "analyst_comment": "Validating DNS ownership",
                },
            )
            self.assertEqual(update_response.status_code, 200)
            self.assertEqual(update_response.json()["remediation_status"], "Investigating")

            health_response = await client.get("/health")
            self.assertEqual(health_response.status_code, 200)
            self.assertTrue(health_response.json()["database"]["enabled"])

            database_response = await client.get(
                "/database", params={"scan_limit": 10, "result_limit": 10}
            )
            self.assertEqual(database_response.status_code, 200)
            database_payload = database_response.json()
            self.assertEqual(database_payload["database"]["type"], "SQLite")
            self.assertTrue(database_payload["database"]["read_only"])
            self.assertGreaterEqual(database_payload["scans"]["total"], 1)
            self.assertGreaterEqual(database_payload["scan_results"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
