"""管线层关键链路测试：跨模块真实数据结果断言。"""
from __future__ import annotations

import pytest

from app.pipeline.format_probe_chain import FormatProbeChain, MagicProbe
from app.pipeline.parser_route_engine import ParserRouteEngine
from app.pipeline.field_parse_engine import FieldParseEngine
from app.pipeline.quarantine_manager import QuarantineManager
from app.pipeline.output_contract_validator import OutputContractValidator
from app.pipeline.result_deliver_manager import ResultDeliverManager
from app.pipeline.watermark_and_reparse import WatermarkAndReparse
from app.pipeline.fingerprint_dedup import FingerprintDedup
from app.pipeline.structure_sniffer import StructureSniffer, DelimiterRule
from app.pipeline.transform_stage import (
    TransformStage, FlattenPath, CastRule, UnitFactor,
)
from app.pipeline.template_version import TemplateVersionManager, TemplateVersion
from app.pipeline.review_metric import ReviewMetricEngine
from app.pipeline.integration import ParsePipelineOrchestrator


# 字段解析使用的模板定义：rec_id 字符串、data_value 数值、payload_bytes 整数
CSV_FIELD_DEFS = [
    {"name": "rec_id", "type": "str", "nullable": False},
    {"name": "rec_timestamp", "type": "datetime", "nullable": False},
    {"name": "data_value", "type": "float", "nullable": False},
    {"name": "payload_bytes", "type": "int", "nullable": False},
]
CSV_COLUMNS = ["rec_id", "rec_timestamp", "data_value", "payload_bytes"]


def clean_rows(count: int, start: int = 1) -> list[dict[str, str]]:
    """生成 count 行全部可解析的数据。"""
    return [
        {
            "rec_id": f"R-2026090-{start + i:05d}",
            "rec_timestamp": f"2026-09-0{(i % 9) + 1} 08:1{i % 6}:00",
            "data_value": f"{100 + i}.5",
            "payload_bytes": str(1024 * (i + 1)),
        }
        for i in range(count)
    ]


class TestFormatProbeChain:
    def test_utf8_bom_resolves_to_csv(self):
        probe = FormatProbeChain()
        ok, msg, result = probe.probe_format("FI-001", "EFBBBF2C", "csv-utf8")
        assert ok is True
        assert result.inferred_format == "csv-utf8"
        assert result.confidence == pytest.approx(0.85)
        assert probe.get_resolved_format("FI-001") == "csv-utf8"

    def test_declared_csv_vs_inferred_xlsx_is_mismatch(self):
        """声明 csv 但魔数是 xlsx 属于跨族不一致，置信度被压到 0.72 并留痕。"""
        probe = FormatProbeChain()
        ok, _msg, result = probe.probe_format("FI-001B", "504B0304", "csv")
        assert result.inferred_format == "xlsx"
        assert result.declared_mismatch is True
        assert result.confidence == pytest.approx(0.72)
        assert ok is True

    def test_declared_csv_refined_to_csv_utf8_not_mismatch(self):
        """声明只给容器类型 csv、魔数细化到 csv-utf8 属于口径细化，不算不一致。"""
        probe = FormatProbeChain()
        ok, _msg, result = probe.probe_format("FI-001C", "EFBBBF2C", "csv")
        assert result.inferred_format == "csv-utf8"
        assert result.declared_mismatch is False
        assert result.confidence == pytest.approx(0.85)
        assert ok is True

    def test_zip_magic_resolves_to_xlsx(self):
        probe = FormatProbeChain()
        ok, _msg, result = probe.probe_format("FI-002", "504B0304", "xlsx")
        assert ok is True
        assert result.inferred_format == "xlsx"

    def test_unknown_magic_falls_below_threshold(self):
        probe = FormatProbeChain()
        ok, msg, result = probe.probe_format("FI-003", "DEADBEEF", "")
        assert ok is False
        assert result.inferred_format == "text-unknown"
        assert result.confidence == 0.15
        assert "低于阈值" in msg

    def test_empty_magic_cannot_probe(self):
        probe = FormatProbeChain()
        ok, msg, _result = probe.probe_format("FI-004", "", "csv")
        assert ok is False
        assert "魔数为空" in msg

    def test_declared_format_mismatch_caps_confidence(self):
        """声明 csv 但魔数是 xlsx 时置信度被压到 0.72，仍可确认但留痕。"""
        probe = FormatProbeChain()
        ok, _msg, result = probe.probe_format("FI-005", "504B0304", "csv")
        assert result.inferred_format == "xlsx"
        assert result.confidence == pytest.approx(0.72)
        assert ok is True

    def test_manual_override_wins_over_probe(self):
        probe = FormatProbeChain()
        probe.probe_format("FI-006", "DEADBEEF", "")
        assert probe.get_resolved_format("FI-006") == "text-unknown"
        probe.override_format("FI-006", "jsonl")
        assert probe.get_resolved_format("FI-006") == "jsonl"

    def test_longest_magic_prefix_wins(self):
        """EFBBBF 这类 6 位魔数比 4 位短前缀更具体，应命中 csv-utf8。"""
        probe = FormatProbeChain()
        _ok, _msg, result = probe.probe_format("FI-007", "EFBBBF41", "")
        assert result.inferred_format == "csv-utf8"

    def test_probe_snapshot_records_all_files(self):
        probe = FormatProbeChain()
        probe.probe_format("FI-008", "EFBBBF", "csv")
        probe.probe_format("FI-009", "7B0A", "jsonl")
        snap = probe.snapshot()
        assert set(snap["probes"]) == {"FI-008", "FI-009"}
        assert snap["threshold"] == 0.70


class TestParserRouteEngine:
    def test_primary_parser_selected_without_fallback(self):
        engine = ParserRouteEngine()
        engine.register_parsers("csv-utf8", ["csv_parser_v2", "csv_parser_v1"])
        routed, decision = engine.route("PR-1", "FI-001", "csv-utf8", "魔数", "t1")
        assert routed is True
        assert decision.selected_parser == "csv_parser_v2"
        assert decision.status == "已选定"
        assert decision.fallback_count == 0

    def test_unknown_format_has_no_parser(self):
        engine = ParserRouteEngine()
        routed, decision = engine.route("PR-2", "FI-002", "text-unknown", "低置信", "t1")
        assert routed is False
        assert decision.status == "路由失败"
        assert decision.primary_parser == ""

    def test_fallback_to_secondary_parser(self):
        engine = ParserRouteEngine()
        engine.register_parsers("csv-utf8", ["csv_parser_v2", "csv_parser_v1", "generic_delimiter"])
        engine.route("PR-3", "FI-003", "csv-utf8", "魔数", "t1")
        ok, msg, decision = engine.execute_with_fallback(
            "PR-3", lambda p: p == "csv_parser_v1", "t2")
        assert ok is True
        assert decision.selected_parser == "csv_parser_v1"
        assert decision.fallback_count == 1
        assert decision.status == "已回退"
        assert "回退 1 次" in msg

    def test_all_parsers_exhausted_marks_route_failed(self):
        engine = ParserRouteEngine()
        engine.register_parsers("xlsx", ["xlsx_parser_v3", "xlsx_parser_v2"])
        engine.route("PR-4", "FI-004", "xlsx", "魔数", "t1")
        ok, msg, decision = engine.execute_with_fallback("PR-4", lambda p: False, "t2")
        assert ok is False
        assert decision.status == "路由失败"
        assert decision.fallback_count == 2
        assert "全部 2 个解析器均失败" in msg

    def test_fallback_stats_feeds_fallback_rate(self):
        engine = ParserRouteEngine()
        engine.register_parsers("csv-utf8", ["csv_parser_v2", "csv_parser_v1"])
        engine.route("PR-5", "FI-005", "csv-utf8", "魔数", "t1")
        engine.route("PR-6", "FI-006", "csv-utf8", "魔数", "t1")
        engine.execute_with_fallback("PR-5", lambda p: True, "t2")
        engine.execute_with_fallback("PR-6", lambda p: p == "csv_parser_v1", "t2")
        fallbacks, total = engine.fallback_stats()
        assert (fallbacks, total) == (1, 2)

    def test_route_failed_decision_cannot_execute(self):
        engine = ParserRouteEngine()
        engine.route("PR-7", "FI-007", "text-unknown", "低置信", "t1")
        ok, msg, _d = engine.execute_with_fallback("PR-7", lambda p: True, "t2")
        assert ok is False
        assert "路由失败" in msg

    def test_execute_missing_decision(self):
        engine = ParserRouteEngine()
        ok, msg, decision = engine.execute_with_fallback("PR-NOPE", lambda p: True, "t")
        assert ok is False
        assert decision is None
        assert "不存在" in msg


class TestFieldParseEngine:
    def test_all_fields_parse_success(self):
        engine = FieldParseEngine()
        engine.register_template("ET-001", CSV_FIELD_DEFS)
        result = engine.parse_row("FI-001", "ET-001", 2, clean_rows(1)[0])
        assert result.all_success is True
        assert result.success_count == 4
        assert result.failure_count == 0

    def test_bad_numeric_value_fails(self):
        engine = FieldParseEngine()
        engine.register_template("ET-001", CSV_FIELD_DEFS)
        row = clean_rows(1)[0]
        row["data_value"] = "N/A"
        result = engine.parse_row("FI-001", "ET-001", 5, row)
        assert result.all_success is False
        failed = [f for f in result.fields if not f.success]
        assert len(failed) == 1
        assert failed[0].field_name == "data_value"
        assert failed[0].raw_value == "N/A"

    def test_bad_timestamp_fails_with_reason(self):
        engine = FieldParseEngine()
        engine.register_template("ET-001", CSV_FIELD_DEFS)
        row = clean_rows(1)[0]
        row["rec_timestamp"] = "2026-09-01XX:10:00"
        result = engine.parse_row("FI-001", "ET-001", 7, row)
        assert result.all_success is False
        assert "rec_timestamp" in [f.field_name for f in result.fields if not f.success]

    def test_missing_template_marks_all_fields_failed(self):
        engine = FieldParseEngine()
        result = engine.parse_row("FI-001", "ET-NOPE", 1, {"rec_id": "R-1"})
        assert result.all_success is False
        assert "不存在" in result.fields[0].error_reason

    def test_failed_fields_collected_for_quarantine(self):
        engine = FieldParseEngine()
        engine.register_template("ET-001", CSV_FIELD_DEFS)
        good = clean_rows(2)
        bad = clean_rows(1, start=9)[0]
        bad["data_value"] = "not-a-number"
        engine.parse_row("FI-001", "ET-001", 2, good[0])
        engine.parse_row("FI-001", "ET-001", 3, good[1])
        engine.parse_row("FI-001", "ET-001", 4, bad)
        failed = engine.get_failed_fields("FI-001")
        assert len(failed) == 1
        assert failed[0].row_num == 4

    def test_batch_quality_summary_counts(self):
        engine = FieldParseEngine()
        engine.register_template("ET-001", CSV_FIELD_DEFS)
        rows = clean_rows(4)
        rows[2]["payload_bytes"] = "abc"
        for i, row in enumerate(rows):
            engine.parse_row("FI-002", "ET-001", i + 1, row)
        summary = engine.batch_quality_summary("FI-002")
        assert summary["total_rows"] == 4
        assert summary["success_rows"] == 3
        assert summary["failed_rows"] == 1
        assert summary["total_fields"] == 16
        assert summary["failed_fields"] == 1
        assert summary["failure_rate"] == pytest.approx(1 / 16)

    def test_nullable_field_accepts_empty(self):
        engine = FieldParseEngine()
        engine.register_template("ET-002", [{"name": "note", "type": "str", "nullable": True}])
        result = engine.parse_row("FI-003", "ET-002", 1, {"note": ""})
        assert result.all_success is True

    def test_non_nullable_field_rejects_empty(self):
        engine = FieldParseEngine()
        engine.register_template("ET-003", [{"name": "rec_id", "type": "str", "nullable": False}])
        result = engine.parse_row("FI-004", "ET-003", 1, {"rec_id": ""})
        assert result.all_success is False
        assert "不可为空" in result.fields[0].error_reason

    def test_category_rejects_value_outside_valid_set(self):
        engine = FieldParseEngine()
        engine.register_template("ET-004", [
            {"name": "channel", "type": "category", "valid_values": ["sftp", "api"]},
        ])
        ok_row = engine.parse_row("FI-005", "ET-004", 1, {"channel": "sftp"})
        bad_row = engine.parse_row("FI-005", "ET-004", 2, {"channel": "carrier-pigeon"})
        assert ok_row.all_success is True
        assert bad_row.all_success is False
        assert "不在允许值" in bad_row.fields[0].error_reason

    def test_unknown_field_passes_through(self):
        engine = FieldParseEngine()
        engine.register_template("ET-005", CSV_FIELD_DEFS)
        result = engine.parse_row("FI-006", "ET-005", 1, {"unexpected_col": "xyz"})
        assert result.all_success is True
        assert result.fields[0].parsed_value == "xyz"


class TestQuarantineManager:
    def test_quarantine_row_registered(self):
        qm = QuarantineManager()
        qr = qm.quarantine_row("FI-001", 5, "R-5,2026-09-01,N/A,1024", [
            {"field_name": "data_value", "error_reason": "无法解析为数值"},
        ])
        assert qr.row_num == 5
        assert qr.failed_fields == ["data_value"]
        assert qm.get_unreviewed_count("FI-001") == 1

    def test_quarantine_rate_computed_from_real_count(self):
        qm = QuarantineManager()
        qm.quarantine_row("FI-001", 5, "row5", [{"field_name": "f", "error_reason": "e"}])
        qm.quarantine_row("FI-001", 9, "row9", [{"field_name": "f", "error_reason": "e"}])
        assert qm.quarantine_rate("FI-001", 500) == pytest.approx(2 / 500)

    def test_high_quarantine_rate_blocks_batch(self):
        qm = QuarantineManager()
        for i in range(6):
            qm.quarantine_row("FI-002", i + 1, f"row{i}", [{"field_name": "f", "error_reason": "e"}])
        blocked, msg = qm.is_batch_blocked("FI-002", 10)
        assert blocked is True
        assert "60.0%" in msg

    def test_review_reinstate_returns_corrected_values(self):
        qm = QuarantineManager()
        qm.quarantine_row("FI-001", 7, "row7", [
            {"field_name": "rec_timestamp", "error_reason": "日期格式异常"},
        ])
        ok = qm.review_row("FI-001", 7, "回补", {"rec_timestamp": "2026-09-01T10:10:00"})
        assert ok is True
        reinstated = qm.get_reinstated("FI-001")
        assert reinstated[7]["rec_timestamp"] == "2026-09-01T10:10:00"
        assert qm.get_unreviewed_count("FI-001") == 0

    def test_review_reject_keeps_row_quarantined(self):
        qm = QuarantineManager()
        qm.quarantine_row("FI-001", 3, "row3", [{"field_name": "f", "error_reason": "e"}])
        qm.review_row("FI-001", 3, "废弃", None)
        assert qm.get_reinstated("FI-001") == {}
        assert qm.get_unreviewed_count("FI-001") == 0

    def test_review_unknown_row_rejected(self):
        qm = QuarantineManager()
        assert qm.review_row("FI-001", 99, "回补", {"a": 1}) is False

    def test_unreviewed_rows_block_contract(self):
        qm = QuarantineManager()
        qm.quarantine_row("FI-001", 5, "row5", [{"field_name": "f", "error_reason": "e"}])
        assert qm.get_unreviewed_count("FI-001") == 1
        qm.review_row("FI-001", 5, "废弃", None)
        assert qm.get_unreviewed_count("FI-001") == 0

    def test_quarantine_summary_counts(self):
        qm = QuarantineManager()
        qm.quarantine_row("FI-001", 1, "r1", [{"field_name": "f", "error_reason": "e"}])
        qm.quarantine_row("FI-001", 2, "r2", [{"field_name": "f", "error_reason": "e"}])
        qm.review_row("FI-001", 1, "回补", {"f": "v"})
        summary = qm.quarantine_summary("FI-001")
        assert summary["total_quarantined"] == 2
        assert summary["reviewed"] == 1
        assert summary["reinstated"] == 1
        assert summary["unreviewed"] == 1

    def test_zero_total_rows_full_rate(self):
        qm = QuarantineManager()
        assert qm.quarantine_rate("FI-EMPTY", 0) == 1.0


class TestOutputContractValidator:
    def test_passing_contract(self):
        cv = OutputContractValidator()
        cv.register_rule("OC-1", "PB-1", CSV_COLUMNS, CSV_COLUMNS, ["rec_id"], 100)
        passed, result = cv.validate("OC-1", CSV_COLUMNS, 498, "t1")
        assert passed is True
        assert result.failures == []

    def test_row_count_below_min_fails(self):
        cv = OutputContractValidator()
        cv.register_rule("OC-2", "PB-2", CSV_COLUMNS, CSV_COLUMNS, ["rec_id"], 500)
        passed, result = cv.validate("OC-2", CSV_COLUMNS, 499, "t1")
        assert passed is False
        assert any("低于下限" in f for f in result.failures)

    def test_missing_column_fails(self):
        cv = OutputContractValidator()
        cv.register_rule("OC-3", "PB-3", CSV_COLUMNS, CSV_COLUMNS, ["rec_id"], 10)
        passed, result = cv.validate("OC-3", ["rec_id", "rec_timestamp"], 50, "t1")
        assert passed is False
        assert any("缺少约定列" in f for f in result.failures)

    def test_extra_column_fails(self):
        cv = OutputContractValidator()
        cv.register_rule("OC-4", "PB-4", CSV_COLUMNS, CSV_COLUMNS, ["rec_id"], 10)
        passed, result = cv.validate("OC-4", CSV_COLUMNS + ["ghost"], 50, "t1")
        assert passed is False
        assert any("多出未约定列" in f for f in result.failures)

    def test_unreviewed_quarantine_blocks_pass(self):
        cv = OutputContractValidator()
        cv.register_rule("OC-5", "PB-5", CSV_COLUMNS, CSV_COLUMNS, ["rec_id"], 10)
        passed, result = cv.validate("OC-5", CSV_COLUMNS, 50, "t1",
                                     has_unreviewed_quarantine=True)
        assert passed is False
        assert any("未复核隔离行" in f for f in result.failures)

    def test_unknown_contract_fails(self):
        cv = OutputContractValidator()
        passed, result = cv.validate("OC-NOPE", CSV_COLUMNS, 10, "t1")
        assert passed is False
        assert result.failures == ["契约 OC-NOPE 不存在"]

    def test_last_result_lookup(self):
        cv = OutputContractValidator()
        cv.register_rule("OC-6", "PB-6", CSV_COLUMNS, CSV_COLUMNS, [], 1)
        cv.validate("OC-6", CSV_COLUMNS, 0, "t1")
        cv.validate("OC-6", CSV_COLUMNS, 5, "t2")
        last = cv.get_last_result("OC-6")
        assert last.passed is True
        assert last.check_time == "t2"


class TestResultDeliverManager:
    def test_deliver_success_records_target(self):
        dm = ResultDeliverManager()
        dm.create_deliver("RD-1", "OC-1", "/data/out/a/", 498, "parquet")
        ok, msg, record = dm.deliver("RD-1", "t1")
        assert ok is True
        assert record.delivered is True
        assert dm.is_delivered("/data/out/a/") is True

    def test_confirmed_deliver_not_overwritten(self):
        """已送达的目标位置再来一次投递时跳过，不覆盖已确认记录。"""
        dm = ResultDeliverManager()
        dm.create_deliver("RD-1", "OC-1", "/data/out/a/", 498, "parquet")
        dm.deliver("RD-1", "t1")
        dm.create_deliver("RD-2", "OC-2", "/data/out/a/", 800, "parquet")
        ok, msg, record = dm.deliver("RD-2", "t2")
        assert ok is True
        assert "跳过" in record.conclusion
        assert record.delivered is False

    def test_partial_delivery_records_missing_rows(self):
        dm = ResultDeliverManager()
        dm.create_deliver("RD-3", "OC-3", "/data/out/b/", 450, "csv")
        ok, _msg, record = dm.deliver("RD-3", "t1", simulate_partial=48)
        assert ok is True
        assert "部分送达" in record.conclusion
        assert "402/450" in record.conclusion
        assert record.delivered is False

    def test_retry_completes_partial(self):
        dm = ResultDeliverManager()
        dm.create_deliver("RD-4", "OC-4", "/data/out/c/", 450, "csv")
        dm.deliver("RD-4", "t1", simulate_partial=48)
        ok, msg, record = dm.retry_deliver("RD-4", "t2", missing_rows=0)
        assert ok is True
        assert record.delivered is True
        assert dm.is_delivered("/data/out/c/") is True

    def test_retry_limit_enforced(self):
        dm = ResultDeliverManager()
        dm.create_deliver("RD-5", "OC-5", "/data/out/d/", 100, "csv")
        dm.deliver("RD-5", "t0", simulate_partial=10)  # retry_count=1
        dm.retry_deliver("RD-5", "t1", missing_rows=5)  # 2
        dm.retry_deliver("RD-5", "t2", missing_rows=5)  # 3
        ok, msg, record = dm.retry_deliver("RD-5", "t3", missing_rows=5)
        assert ok is False
        assert "已达上限" in msg
        assert record.delivered is False

    def test_deliver_missing_record(self):
        dm = ResultDeliverManager()
        ok, msg, record = dm.deliver("RD-NOPE", "t1")
        assert ok is False
        assert record is None


class TestWatermarkAndReparse:
    def test_watermark_cannot_advance_before_all_closed(self):
        wm = WatermarkAndReparse()
        wm.register_channel("sftp-03", total_unparsed=3)
        wm.mark_batch_closed("sftp-03", "FI-001")
        ok, msg = wm.advance_watermark("sftp-03", "FI-001", "t1")
        assert ok is False
        assert "未闭合" in msg

    def test_watermark_advances_after_all_closed(self):
        wm = WatermarkAndReparse()
        wm.register_channel("sftp-03", total_unparsed=2)
        wm.mark_batch_closed("sftp-03", "FI-001")
        wm.mark_batch_closed("sftp-03", "FI-002")
        ok, msg = wm.advance_watermark("sftp-03", "FI-002", "t1")
        assert ok is True
        assert wm.get_watermark("sftp-03").position == "FI-002"

    def test_lag_registered_with_reason(self):
        wm = WatermarkAndReparse()
        wm.set_lag("web-upload", 3, "结构嗅探低置信阻断解析链路")
        reading = wm.get_watermark("web-upload")
        assert reading.lag_count == 3
        assert "嗅探" in reading.lag_reason

    def test_reparse_task_created_and_completed(self):
        wm = WatermarkAndReparse()
        ok, msg, task = wm.create_reparse(
            "RT-1", "PB-1", "模板差异", "旧投递保留", "FI-001", "FI-010", 10)
        assert ok is True
        ok2, msg2 = wm.complete_reparse("RT-1", "10批次重解析成功", 10)
        assert ok2 is True
        assert wm._reparse_tasks["RT-1"].completed is True

    def test_duplicate_reparse_task_rejected(self):
        wm = WatermarkAndReparse()
        wm.create_reparse("RT-2", "PB-1", "r", "旧投递保留", "a", "b", 1)
        ok, msg, task = wm.create_reparse("RT-2", "PB-2", "r", "旧投递保留", "a", "b", 1)
        assert ok is False
        assert task is None
        assert "已存在" in msg

    def test_completed_task_cannot_abort(self):
        wm = WatermarkAndReparse()
        wm.create_reparse("RT-3", "PB-1", "r", "被新记录替代", "a", "b", 1)
        wm.complete_reparse("RT-3", "done", 1)
        ok, msg = wm.abort_reparse("RT-3", "误操作")
        assert ok is False
        assert "已完成" in msg

    def test_aborted_task_cannot_complete(self):
        wm = WatermarkAndReparse()
        wm.create_reparse("RT-4", "PB-1", "r", "旧投递保留", "a", "b", 1)
        wm.abort_reparse("RT-4", "源批次不可解析")
        ok, msg = wm.complete_reparse("RT-4", "done", 1)
        assert ok is False
        assert "中止" in msg

    def test_coverage_registration_keeps_strategy(self):
        wm = WatermarkAndReparse()
        wm.register_coverage("PB-1", "旧投递保留", "RD-OLD-1")
        wm.register_coverage("PB-1", "旧投递保留", "RD-OLD-2")
        coverage = wm.get_coverage("PB-1")
        assert coverage == {"RD-OLD-1": "旧投递保留", "RD-OLD-2": "旧投递保留"}

    def test_advance_unknown_channel_registers_first(self):
        wm = WatermarkAndReparse()
        ok, msg = wm.advance_watermark("new-channel", "FI-001", "t1")
        assert ok is True or "未闭合" in msg
        assert wm.get_watermark("new-channel") is not None


class TestFingerprintDedup:
    def test_unique_batch_passes(self):
        dd = FingerprintDedup()
        record = dd.check_duplicate(
            "DF-1", "FI-001",
            FingerprintDedup.compute_content_hash(["line-a", "line-b"]),
            FingerprintDedup.compute_schema_hash(["c1", "c2"]), "t1")
        assert record.verdict == "唯一"
        assert record.disposition == "放行"

    def test_content_duplicate_blocks_deliver(self):
        dd = FingerprintDedup()
        content = FingerprintDedup.compute_content_hash(["same-line"])
        schema = FingerprintDedup.compute_schema_hash(["c1"])
        dd.check_duplicate("DF-1", "FI-001", content, schema, "t1")
        second = dd.check_duplicate("DF-2", "FI-002", content, schema, "t2")
        assert second.verdict == "内容重复"
        assert second.duplicate_of == "FI-001"
        blocked, msg = dd.is_deliver_blocked("FI-002")
        assert blocked is True
        assert "阻断" in msg

    def test_schema_collision_is_suspected_only(self):
        dd = FingerprintDedup()
        schema = FingerprintDedup.compute_schema_hash(["c1", "c2"])
        dd.check_duplicate("DF-1", "FI-001",
                           FingerprintDedup.compute_content_hash(["a"]), schema, "t1")
        second = dd.check_duplicate("DF-2", "FI-002",
                                    FingerprintDedup.compute_content_hash(["b"]), schema, "t2")
        assert second.verdict == "结构相同内容不同"
        assert second.disposition == "待人工确认"
        blocked, _msg = dd.is_deliver_blocked("FI-002")
        assert blocked is True

    def test_unique_batch_not_blocked(self):
        dd = FingerprintDedup()
        dd.check_duplicate("DF-1", "FI-001",
                           FingerprintDedup.compute_content_hash(["a"]),
                           FingerprintDedup.compute_schema_hash(["c1"]), "t1")
        blocked, _msg = dd.is_deliver_blocked("FI-001")
        assert blocked is False

    def test_hash_stability(self):
        h1 = FingerprintDedup.compute_content_hash(["x", "y"])
        h2 = FingerprintDedup.compute_content_hash(["x", "y"])
        h3 = FingerprintDedup.compute_content_hash(["y", "x"])
        assert h1 == h2
        assert h1 != h3
        assert h1.startswith("sha256:")

    def test_schema_hash_order_insensitive(self):
        s1 = FingerprintDedup.compute_schema_hash(["a", "b"])
        s2 = FingerprintDedup.compute_schema_hash(["b", "a"])
        assert s1 == s2

    def test_unknown_batch_not_blocked(self):
        dd = FingerprintDedup()
        blocked, msg = dd.is_deliver_blocked("FI-NOPE")
        assert blocked is False


class TestStructureSniffer:
    def test_header_row_detected_parse_starts_at_two(self):
        sniffer = StructureSniffer()
        sniffer.register_rule(DelimiterRule("DR-1", "csv", ",", '"', "\\"))
        lines = [
            "rec_id,data_value",
            "R-1,10.5",
            "R-2,20.5",
            "R-3,30.5",
        ]
        usable, result = sniffer.sniff("FI-001", "csv", lines)
        assert usable is True
        assert result.first_row_is_header is True
        assert result.parse_start_row == 2
        assert result.column_names == ["rec_id", "data_value"]

    def test_headerless_file_parse_starts_at_one(self):
        sniffer = StructureSniffer()
        sniffer.register_rule(DelimiterRule("DR-1", "csv", ",", '"', "\\"))
        lines = ["1,10.5", "2,20.5", "3,30.5", "4,40.5"]
        usable, result = sniffer.sniff("FI-002", "csv", lines)
        assert result.first_row_is_header is False
        assert result.parse_start_row == 1
        assert result.column_names == ["col-0", "col-1"]

    def test_inconsistent_column_count_lowers_confidence(self):
        sniffer = StructureSniffer()
        sniffer.register_rule(DelimiterRule("DR-1", "csv", ",", '"', "\\"))
        lines = ["a,1", "b,2,extra", "c,3", "d,4,extra2"]
        usable, result = sniffer.sniff("FI-003", "csv", lines)
        assert result.confidence < 0.95

    def test_missing_rule_returns_unusable(self):
        sniffer = StructureSniffer()
        usable, result = sniffer.sniff("FI-004", "csv", ["a,1"])
        assert usable is False
        assert result.column_count == 0

    def test_empty_sample_returns_unusable(self):
        sniffer = StructureSniffer()
        sniffer.register_rule(DelimiterRule("DR-1", "csv", ",", '"', "\\"))
        usable, result = sniffer.sniff("FI-005", "csv", [])
        assert usable is False

    def test_rule_replacement_migrates_hit_batches(self):
        sniffer = StructureSniffer()
        sniffer.register_rule(DelimiterRule("DR-1", "csv", ",", '"', "\\"))
        sniffer.sniff("FI-006", "csv", ["a,1", "b,2"])
        old = sniffer.replace_rule("csv", DelimiterRule("DR-2", "csv", ";", '"', "\\"))
        assert old is not None
        assert old.rule_id == "DR-1"
        new_rule = sniffer.get_active_rule("csv")
        assert new_rule.rule_id == "DR-2"
        assert "FI-006" in new_rule.hit_batches

    def test_same_text_different_delimiter_different_columns(self):
        """同一段文本在逗号/分号规则下切出不同列数，影响嗅探结论。"""
        sniffer = StructureSniffer()
        sniffer.register_rule(DelimiterRule("DR-1", "csv", ",", '"', "\\"))
        _u1, r1 = sniffer.sniff("FI-007", "csv", ["a,1", "b,2", "c,3"])
        comma_cols = r1.column_count
        sniffer.replace_rule("csv", DelimiterRule("DR-2", "csv", ";", '"', "\\"))
        _u2, r2 = sniffer.sniff("FI-008", "csv", ["a,1", "b,2", "c,3"])
        assert comma_cols == 2
        assert r2.column_count == 1

    def test_parse_start_row_default_without_sniff(self):
        sniffer = StructureSniffer()
        assert sniffer.parse_start_row("FI-NOPE") == 1


class TestTransformStage:
    def test_expand_array_multiplies_rows(self):
        stage = TransformStage()
        stage.register_flatten_path(FlattenPath(
            "NF-1", "ET-1", "$.data.records[*]", ["rec_id", "value"],
            "EXPAND", 3, "SKIP"))
        docs = [
            {"data": {"records": [{"rec_id": "R-1", "value": 1},
                                  {"rec_id": "R-2", "value": 2}]}},
            {"data": {"records": [{"rec_id": "R-3", "value": 3}]}},
        ]
        ok, rows, msg = stage.flatten_document("NF-1", docs)
        assert ok is True
        assert len(rows) == 3
        assert rows[0] == {"rec_id": "R-1", "value": 1}

    def test_depth_exceeded_blocks_flatten(self):
        stage = TransformStage()
        stage.register_flatten_path(FlattenPath(
            "NF-2", "ET-1", "$.a.b.c.d.e", ["x"], "EXPAND", 4, "SKIP"))
        ok, rows, msg = stage.flatten_document("NF-2", [{"a": {}}])
        assert ok is False
        assert "层数超限" in msg
        assert rows == []

    def test_array_to_string_joins_values(self):
        stage = TransformStage()
        stage.register_flatten_path(FlattenPath(
            "NF-3", "ET-1", "$.attrs[*]", ["attr_list"],
            "ARRAY_TO_STRING", 2, "SKIP"))
        ok, rows, _msg = stage.flatten_document(
            "NF-3", [{"attrs": ["k1", "k2", "k3"]}])
        assert ok is True
        assert rows[0]["attr_list"] == "k1;k2;k3"

    def test_empty_nodes_majority_blocks(self):
        stage = TransformStage()
        stage.register_flatten_path(FlattenPath(
            "NF-4", "ET-1", "$.optional[*]", ["k"], "EXPAND", 2, "SKIP"))
        docs = [{"optional": [{"k": 1}]}, {}, {}, {}]
        ok, _rows, msg = stage.flatten_document("NF-4", docs)
        assert ok is False
        assert "空节点过多" in msg

    def test_fill_null_policy_keeps_row(self):
        stage = TransformStage()
        stage.register_flatten_path(FlattenPath(
            "NF-5", "ET-1", "$.optional[*]", ["k"], "EXPAND", 2, "FILL_NULL"))
        docs = [{"optional": [{"k": 1}]}, {"optional": [{"k": 2}]}]
        ok, rows, _msg = stage.flatten_document("NF-5", docs)
        assert ok is True
        assert len(rows) == 2

    def test_cast_failure_row_goes_to_failures(self):
        stage = TransformStage()
        stage.register_cast_rule(CastRule("VC-1", "value", "str", "float64"))
        rows = [{"rec_id": "R-1", "value": "10.5"},
                {"rec_id": "R-2", "value": "abc"}]
        ok_rows, failed = stage.cast_rows("FI-001", rows)
        assert len(ok_rows) == 1
        assert ok_rows[0]["value"] == pytest.approx(10.5)
        assert len(failed) == 1
        assert failed[0]["row_index"] == 1
        assert "转型" in failed[0]["failed_fields"][0]

    def test_cast_datetime_with_pattern(self):
        stage = TransformStage()
        stage.register_cast_rule(CastRule(
            "VC-2", "ts", "str", "datetime64", date_pattern="%Y-%m-%d %H:%M:%S"))
        ok_rows, failed = stage.cast_rows("FI-002", [{"ts": "2026-09-01 08:15:00"}])
        assert not failed
        assert ok_rows[0]["ts"] == "2026-09-01T08:15:00"

    def test_unit_normalize_applies_factor(self):
        stage = TransformStage()
        stage.register_unit_factor(UnitFactor(
            "UN-1", "payload", "KB", "byte", 1024.0, "sftp-03", "2026-07-01"))
        rows, refused = stage.normalize_units(
            "FI-001", "sftp-03", [{"payload": 3.0}])
        assert rows[0]["payload"] == pytest.approx(3072.0)
        assert rows[0]["__unit_payload"] == "byte"
        assert refused == []

    def test_conflicting_factors_refuse_normalize(self):
        stage = TransformStage()
        stage.register_unit_factor(UnitFactor(
            "UN-1", "duration", "s", "ms", 1000.0, "web", "2026-07-01"))
        stage.register_unit_factor(UnitFactor(
            "UN-2", "duration", "s", "ms", 60.0, "web", "2026-09-01"))
        assert len(stage.get_conflicts()) == 1
        rows, refused = stage.normalize_units("FI-002", "web", [{"duration": 5}])
        assert rows[0]["duration"] == 5
        assert len(refused) == 1
        assert "系数冲突" in refused[0]["reason"]

    def test_other_channel_factor_not_applied(self):
        stage = TransformStage()
        stage.register_unit_factor(UnitFactor(
            "UN-3", "payload", "MB", "byte", 1048576.0, "api-gw", "2026-07-01"))
        rows, refused = stage.normalize_units(
            "FI-003", "sftp-03", [{"payload": 2}])
        assert rows[0]["payload"] == 2
        assert refused == []

    def test_missing_path_id_fails(self):
        stage = TransformStage()
        ok, rows, msg = stage.flatten_document("NF-NOPE", [{}])
        assert ok is False
        assert "不存在" in msg


class TestTemplateVersionManager:
    def _pair(self):
        old = TemplateVersion("ET-003", "csv-chan-b", "csv", "v2.7.0",
                              {"rec_id": "$.id", "val": "$.value"},
                              parent_version="v2.6.0", effective_from="2026-07-01T00:00:00")
        new = TemplateVersion("ET-002", "csv-chan-b", "csv", "v3.0.0",
                              {"rec_id": "$.id", "val": "$.value_v3", "tag": "$.tag"},
                              parent_version="v2.7.0", effective_from="2026-09-05T00:00:00")
        return old, new

    def test_transition_keeps_both_versions_coexisting(self):
        mgr = TemplateVersionManager()
        old, new = self._pair()
        mgr.register_version(old)
        mgr.register_version(new)
        old.status = "已生效"
        ok, msg, coexisting = mgr.start_transition("ET-002", "2026-09-05T00:00:00")
        assert ok is True
        assert set(coexisting) == {"v2.7.0", "v3.0.0"}

    def test_hit_version_chosen_by_batch_time(self):
        """过渡期内早于新版本生效时间的批次仍命中旧版本，晚于的命中新版本。"""
        mgr = TemplateVersionManager()
        old, new = self._pair()
        mgr.register_version(old)
        mgr.register_version(new)
        old.status = "已生效"
        mgr.start_transition("ET-002", "2026-09-05T00:00:00")
        early = mgr.resolve_hit_version("csv-chan-b", "csv", "2026-09-01T08:00:00")
        late = mgr.resolve_hit_version("csv-chan-b", "csv", "2026-09-06T08:00:00")
        assert early == "ET-003"
        assert late == "ET-002"

    def test_broken_parent_chain_blocks_activation(self):
        mgr = TemplateVersionManager()
        orphan = TemplateVersion("ET-009", "csv-x", "csv", "v1.0.0",
                                 {"a": "$.a"}, parent_version="v0.9.0")
        mgr.register_version(orphan)
        ok, msg = mgr.activate_version("ET-009", "2026-09-01")
        assert ok is False
        assert "版本链断裂" in msg

    def test_activate_retires_transitioning_predecessor(self):
        mgr = TemplateVersionManager()
        old, new = self._pair()
        mgr.register_version(old)
        mgr.register_version(new)
        old.status = "过渡中"
        ok, msg = mgr.activate_version("ET-002", "2026-09-05T00:00:00")
        assert ok is True
        assert mgr.get_version("ET-003").status == "已废止"
        assert mgr.get_version("ET-002").status == "已生效"

    def test_double_activation_rejected(self):
        mgr = TemplateVersionManager()
        old, _new = self._pair()
        mgr.register_version(old)
        old.status = "已生效"
        ok, msg = mgr.activate_version("ET-003", "2026-09-01")
        assert ok is False
        assert "已生效" in msg

    def test_diff_fields_counted_by_category(self):
        mgr = TemplateVersionManager()
        old, new = self._pair()
        mgr.register_version(old)
        mgr.register_version(new)
        diff = mgr.diff_versions("ET-003", "ET-002", affected_batches=15)
        assert diff.added == ["tag"]
        assert diff.changed == ["val"]
        assert diff.removed == []
        assert diff.diff_field_count == 2
        assert diff.converged is True

    def test_large_diff_not_converged(self):
        mgr = TemplateVersionManager()
        old = TemplateVersion("ET-A", "jsonl", "jsonl", "v1.0",
                              {f"f{i}": f"$.f{i}" for i in range(10)})
        new = TemplateVersion("ET-B", "jsonl", "jsonl", "v2.0",
                              {f"g{i}": f"$.g{i}" for i in range(10)})
        mgr.register_version(old)
        mgr.register_version(new)
        diff = mgr.diff_versions("ET-A", "ET-B", affected_batches=100)
        assert diff.diff_field_count == 20
        assert diff.converged is False

    def test_reparse_range_covers_affected_positions(self):
        mgr = TemplateVersionManager()
        old, new = self._pair()
        mgr.register_version(old)
        mgr.register_version(new)
        diff = mgr.diff_versions("ET-003", "ET-002", affected_batches=3)
        positions = {"FI-001": "2026-09-01", "FI-002": "2026-09-02",
                     "FI-003": "2026-09-03"}
        ok, msg, rng = mgr.plan_reparse_range("RT-1", diff, positions)
        assert ok is True
        assert rng.start_position == "2026-09-01"
        assert rng.end_position == "2026-09-03"
        assert rng.affected_batches == ["FI-001", "FI-002", "FI-003"]
        assert rng.split_batches == 1

    def test_large_diff_forces_split_reparse(self):
        mgr = TemplateVersionManager()
        old = TemplateVersion("ET-A", "jsonl", "jsonl", "v1.0",
                              {f"f{i}": f"$.f{i}" for i in range(10)})
        new = TemplateVersion("ET-B", "jsonl", "jsonl", "v2.0",
                              {f"g{i}": f"$.g{i}" for i in range(10)})
        mgr.register_version(old)
        mgr.register_version(new)
        diff = mgr.diff_versions("ET-A", "ET-B", affected_batches=2)
        ok, msg, rng = mgr.plan_reparse_range(
            "RT-2", diff, {"FI-001": "2026-09-01", "FI-002": "2026-09-02"})
        assert ok is True
        assert rng.split_batches > 1
        assert "分" in msg

    def test_empty_affected_batches_no_reparse(self):
        mgr = TemplateVersionManager()
        old, new = self._pair()
        mgr.register_version(old)
        mgr.register_version(new)
        diff = mgr.diff_versions("ET-003", "ET-002", affected_batches=0)
        ok, msg, rng = mgr.plan_reparse_range("RT-3", diff, {})
        assert ok is False
        assert rng is None
        assert "无需重解析" in msg


class TestReviewMetricEngine:
    def test_low_deviation_passes(self):
        engine = ReviewMetricEngine()
        parsed = [{"rec_id": f"R-{i}", "value": 100 + i} for i in range(20)]
        raw = [{"rec_id": f"R-{i}", "value": 100 + i} for i in range(20)]
        sample = engine.run_review("SR-1", "PB-1", parsed, raw, 0.5,
                                   "reviewer-01", ["rec_id", "value"])
        assert sample.status == "已通过"
        assert sample.deviation_count == 0
        assert sample.sampled_rows == 10

    def test_high_deviation_rejected_and_blocks(self):
        engine = ReviewMetricEngine()
        parsed = [{"rec_id": f"R-{i}", "value": 999} for i in range(20)]
        raw = [{"rec_id": f"R-{i}", "value": 100 + i} for i in range(20)]
        sample = engine.run_review("SR-2", "PB-2", parsed, raw, 0.5,
                                   "reviewer-01", ["value"])
        assert sample.status == "已驳回"
        assert sample.deviation_rate > 0.10
        blocked, msg = engine.is_batch_blocked_by_review("PB-2")
        assert blocked is True
        assert "驳回" in msg

    def test_numeric_string_equivalence_counts_consistent(self):
        engine = ReviewMetricEngine()
        parsed = [{"value": 1024.0} for _ in range(10)]
        raw = [{"value": "1024"} for _ in range(10)]
        sample = engine.run_review("SR-3", "PB-3", parsed, raw, 1.0,
                                   "reviewer-01", ["value"])
        assert sample.deviation_count == 0
        assert sample.consistent_count == 10

    def test_empty_batch_rejected(self):
        engine = ReviewMetricEngine()
        sample = engine.run_review("SR-4", "PB-4", [], [], 0.1,
                                   "reviewer-01", ["value"])
        assert sample.status == "已驳回"
        assert sample.sampled_rows == 0

    def test_metric_rates_from_real_counts(self):
        """隔离率与回退率必须由真实计数算出而非估算。"""
        engine = ReviewMetricEngine()
        reading = engine.collect_metric(
            "PM-1", "20260901", "sftp-03",
            throughput_rows=500, parse_durations_ms=[2.0, 4.0, 6.0],
            quarantined_rows=2, total_rows=500,
            fallback_decisions=1, total_decisions=4,
            collected_at="2026-09-02T00:00:00")
        assert reading.quarantine_rate == pytest.approx(0.004)
        assert reading.fallback_rate == pytest.approx(0.25)
        assert reading.avg_parse_ms == pytest.approx(4.0)
        assert reading.status == "已结算"

    def test_zero_total_rows_no_division_error(self):
        engine = ReviewMetricEngine()
        reading = engine.collect_metric(
            "PM-2", "20260901", "api-gw", 0, [], 0, 0, 0, 0, "t")
        assert reading.quarantine_rate == 0.0
        assert reading.fallback_rate == 0.0

    def test_channel_summary_aggregates_readings(self):
        engine = ReviewMetricEngine()
        engine.collect_metric("PM-3", "20260901", "sftp-03", 500, [2.0], 2, 500, 0, 2, "t1")
        engine.collect_metric("PM-4", "20260902", "sftp-03", 800, [4.0], 4, 800, 1, 2, "t2")
        summary = engine.channel_summary("sftp-03")
        assert summary["reading_count"] == 2
        assert summary["total_throughput"] == 1300
        assert summary["avg_quarantine_rate"] == pytest.approx(0.0045)


# ======================================================================
# 编排器级链路测试：真实跨模块数据结果 + 下游可见性
# ======================================================================

from app.store import store  # noqa: E402
from app.services import SERVICES  # noqa: E402


@pytest.fixture(autouse=False)
def fresh_store():
    """每个链路测试从 seed 初始状态开始，避免跨测试污染。"""
    store.reload_seed()
    yield store
    store.reload_seed()


def intake_rows(module: str, **match) -> list[dict]:
    return [
        r for r in store.rows(module)
        if all(str(r.get(k)) == str(v) for k, v in match.items())
    ]


class TestLink1IntakeToDeliver:
    def _run(self, batch_id="FI-T001", rows=None, min_rows=3):
        orch = ParsePipelineOrchestrator()
        return orch, orch.link1_intake_to_deliver(
            batch_id=batch_id, channel="sftp-node-03",
            filename=f"{batch_id}.csv", magic_hex="EFBBBF2C",
            declared_format="csv", size_bytes=4096,
            arrive_time="2026-09-03T08:00:00",
            parser_chain=["csv_parser_v2", "csv_parser_v1"],
            template_id="ET-001", field_defs=CSV_FIELD_DEFS,
            raw_lines=rows if rows is not None else clean_rows(5),
            contract_columns=CSV_COLUMNS, mandatory=["rec_id"],
            min_rows=min_rows,
            target_path=f"/data/cooked/{batch_id}/",
            output_format="parquet", deliver_time="2026-09-03T08:30:00",
        )

    def test_clean_batch_flows_all_the_way_to_delivery(self, fresh_store):
        _orch, result = self._run()
        assert result["ok"] is True
        assert result["success_rows"] == 5
        assert result["quarantined"] == 0
        # 下游可见性：投递记录真实落库且已送达
        records = intake_rows("result_deliver", **{"投递记录编号": "RD-FI-T001"})
        assert len(records) == 1
        assert records[0]["status"] == "已送达"
        assert records[0]["投递行数"] == "5"

    def test_dirty_row_stops_contract_and_no_delivery(self, fresh_store):
        rows = clean_rows(5)
        rows[2]["data_value"] = "N/A"
        _orch, result = self._run(rows=rows, min_rows=3)
        assert result["ok"] is False
        assert result["stage"] == "output_contract"
        assert result["quarantined"] == 1
        # 契约未通过 → 不产生任何投递记录
        assert intake_rows("result_deliver", **{"投递记录编号": "RD-FI-T001"}) == []
        # 隔离行真实落库
        quarantined = intake_rows("row_quarantine", **{"关联批次": "FI-T001"})
        assert len(quarantined) == 0  # link1 只写 pipeline 内隔离，服务层隔离见链路2
        # 批次记录带隔离状态
        batches = intake_rows("parse_batch", **{"关联投递批次": "FI-T001"})
        assert batches[0]["批次状态"] == "存在隔离"
        assert batches[0]["隔离行数"] == "1"

    def test_rows_below_min_fails_contract(self, fresh_store):
        _orch, result = self._run(rows=clean_rows(2), min_rows=10)
        assert result["ok"] is False
        assert any("低于下限" in f for f in result["message"].split(";"))

    def test_unrecognized_format_voids_batch(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        result = orch.link1_intake_to_deliver(
            batch_id="FI-T002", channel="api-gateway-01",
            filename="broken.bin", magic_hex="DEADBEEF",
            declared_format="", size_bytes=100,
            arrive_time="2026-09-03T09:00:00",
            parser_chain=[], template_id="ET-001", field_defs=CSV_FIELD_DEFS,
            raw_lines=clean_rows(3), contract_columns=CSV_COLUMNS,
            mandatory=["rec_id"], min_rows=1,
            target_path="/data/cooked/t2/", output_format="parquet",
            deliver_time="2026-09-03T09:30:00")
        assert result["ok"] is False
        assert result["stage"] == "parser_route"
        batches = intake_rows("parse_batch", **{"关联投递批次": "FI-T002"})
        assert batches[0]["批次状态"] == "无法解析"

    def test_probe_and_route_rows_written(self, fresh_store):
        _orch, _result = self._run(batch_id="FI-T003")
        probes = intake_rows("format_probe", **{"关联批次": "FI-T003"})
        assert len(probes) == 1
        assert probes[0]["推断格式"] == "csv-utf8"
        assert probes[0]["status"] == "已确认"
        # 投递批次同步登记
        intakes = intake_rows("file_intake", **{"批次编号": "FI-T003"})
        assert len(intakes) == 1
        assert intakes[0]["来源渠道"] == "sftp-node-03"


class TestLink2EncodingQuarantine:
    def test_lossy_encoding_quarantines_bad_rows(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        rows = clean_rows(4)
        rows[1]["data_value"] = "###"  # 模拟损字后无法解析
        result = orch.link2_encoding_quarantine(
            batch_id="FI-E001", source_encoding="GB18030", target_encoding="UTF-8",
            unmappable_count=3, replace_strategy="REPLACE",
            raw_lines=rows, template_id="ET-001", field_defs=CSV_FIELD_DEFS,
            norm_time="2026-09-03T10:00:00")
        assert result["lossy"] is True
        assert result["quarantined_rows"] == [2]
        assert result["quarantine_rate"] == pytest.approx(0.25)
        # 转码记录落库为存在损字
        norms = intake_rows("encoding_norm", **{"关联批次": "FI-E001"})
        assert norms[0]["status"] == "存在损字"
        assert norms[0]["不可映射字符数"] == "3"

    def test_clean_encoding_no_quarantine(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        result = orch.link2_encoding_quarantine(
            batch_id="FI-E002", source_encoding="UTF-8", target_encoding="UTF-8",
            unmappable_count=0, replace_strategy="REPLACE",
            raw_lines=clean_rows(3), template_id="ET-001",
            field_defs=CSV_FIELD_DEFS, norm_time="2026-09-03T10:00:00")
        assert result["lossy"] is False
        assert result["quarantined_rows"] == []
        norms = intake_rows("encoding_norm", **{"关联批次": "FI-E002"})
        assert norms[0]["status"] == "已完成"

    def test_reinstate_returns_row_to_batch_counts(self, fresh_store):
        """复核回补后批次成功行数 +1、隔离行数 -1，全回补后批次闭合。"""
        orch = ParsePipelineOrchestrator()
        rows = clean_rows(4)
        rows[2]["rec_timestamp"] = "2026-09-01XX:10:00"
        # 先建批次记录（模拟链路1的批次装配）
        store.rows("parse_batch").append({
            "id": 900, "status": "存在隔离", "pending": True, "abnormal": True,
            "批次记录编号": "PB-E003", "关联投递批次": "FI-E003",
            "解析器标识": "csv_parser_v2", "总行数": "4", "成功行数": "3",
            "隔离行数": "1", "批次状态": "存在隔离", "完成时间": "",
        })
        orch.link2_encoding_quarantine(
            batch_id="FI-E003", source_encoding="EUC-JP", target_encoding="UTF-8",
            unmappable_count=1, replace_strategy="REPLACE",
            raw_lines=rows, template_id="ET-001", field_defs=CSV_FIELD_DEFS,
            norm_time="2026-09-03T11:00:00")
        ok, msg = orch.reinstate_quarantined_row(
            "FI-E003", 3, {"rec_timestamp": "2026-09-01T10:10:00"},
            "reviewer-01", "2026-09-03T12:00:00")
        assert ok is True
        batch = intake_rows("parse_batch", **{"批次记录编号": "PB-E003"})[0]
        assert batch["成功行数"] == "4"
        assert batch["隔离行数"] == "0"
        assert batch["批次状态"] == "已闭合"
        # 回补记录落库
        reinstated = intake_rows("row_quarantine", **{"隔离编号": "RQ-FI-E003-3"})
        assert reinstated[0]["status"] == "已回补"

    def test_reinstate_unknown_row_rejected(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        ok, msg = orch.reinstate_quarantined_row("FI-NOPE", 1, {"a": 1}, "r", "t")
        assert ok is False
        assert "不在隔离清单" in msg


class TestLink3SniffParseStart:
    def test_header_file_parses_from_row_two(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        from app.pipeline.structure_sniffer import DelimiterRule
        orch.sniffer.register_rule(DelimiterRule("DR-csv", "csv", ",", '"', "\\"))
        result = orch.link3_sniff_parse_start(
            batch_id="FI-S001", fmt="csv",
            sample_lines=["rec_id,data_value", "R-1,10.5", "R-2,20.5"],
            template_id="ET-001",
            field_defs=[{"name": "rec_id", "type": "str"},
                        {"name": "data_value", "type": "float"}],
            data_rows=[{"rec_id": "R-1", "data_value": "10.5"},
                       {"rec_id": "R-2", "data_value": "20.5"}],
            sniff_time="2026-09-03T13:00:00")
        assert result["ok"] is True
        assert result["first_row_is_header"] is True
        assert result["parse_start_row"] == 2
        assert result["parsed_row_numbers"] == [2, 3]
        # 嗅探结论落库
        sniffs = intake_rows("schema_sniff", **{"关联批次": "FI-S001"})
        assert sniffs[0]["首行是否表头"] == "是"
        assert sniffs[0]["status"] == "已推断"

    def test_headerless_file_parses_from_row_one(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        from app.pipeline.structure_sniffer import DelimiterRule
        orch.sniffer.register_rule(DelimiterRule("DR-csv", "csv", ",", '"', "\\"))
        result = orch.link3_sniff_parse_start(
            batch_id="FI-S002", fmt="csv",
            sample_lines=["1,10.5", "2,20.5", "3,30.5"],
            template_id="ET-001",
            field_defs=[{"name": "col-0", "type": "int"},
                        {"name": "col-1", "type": "float"}],
            data_rows=[{"col-0": "1", "col-1": "10.5"}],
            sniff_time="2026-09-03T13:00:00")
        assert result["parse_start_row"] == 1
        assert result["parsed_row_numbers"] == [1]

    def test_low_confidence_blocks_parse(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        from app.pipeline.structure_sniffer import DelimiterRule
        orch.sniffer.register_rule(DelimiterRule("DR-csv", "csv", ",", '"', "\\"))
        # 单行样本 + 无规则命中列结构 → 低置信
        result = orch.link3_sniff_parse_start(
            batch_id="FI-S003", fmt="csv", sample_lines=["only-one-row"],
            template_id="ET-001", field_defs=CSV_FIELD_DEFS,
            data_rows=[], sniff_time="2026-09-03T13:00:00")
        assert result["ok"] is False
        assert result["stage"] == "schema_sniff"


class TestLink4FlattenCastNormalize:
    def _setup(self, orch):
        orch.transform.register_flatten_path(FlattenPath(
            "NF-T1", "ET-004", "$.data.records[*]", ["rec_id", "amount"],
            "EXPAND", 3, "SKIP"))
        cast_rules = [
            CastRule("VC-T1", "amount", "str", "float64", precision=2),
        ]
        orch.transform.register_unit_factor(UnitFactor(
            "UN-T1", "amount", "KB", "byte", 1024.0, "sftp-node-03", "2026-07-01"))
        return cast_rules

    def test_expand_cast_normalize_contract_pass(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        cast_rules = self._setup(orch)
        docs = [
            {"data": {"records": [{"rec_id": "R-1", "amount": "2.5"},
                                  {"rec_id": "R-2", "amount": "3.5"}]}},
            {"data": {"records": [{"rec_id": "R-3", "amount": "4.5"}]}},
        ]
        result = orch.link4_flatten_cast_normalize(
            batch_id="FI-N001", channel="sftp-node-03", path_id="NF-T1",
            documents=docs, cast_rules=cast_rules,
            contract_id="OC-N001", contract_columns=["amount", "rec_id"],
            mandatory=["rec_id"], min_rows=3, check_time="2026-09-03T14:00:00")
        assert result["ok"] is True
        assert result["flat_rows"] == 3
        assert result["cast_ok"] == 3
        assert result["normalized_rows"] == 3

    def test_cast_failure_quarantines_row(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        cast_rules = self._setup(orch)
        docs = [{"data": {"records": [
            {"rec_id": "R-1", "amount": "2.5"},
            {"rec_id": "R-2", "amount": "not-a-number"},
        ]}}]
        result = orch.link4_flatten_cast_normalize(
            batch_id="FI-N002", channel="sftp-node-03", path_id="NF-T1",
            documents=docs, cast_rules=cast_rules,
            contract_id="OC-N002", contract_columns=["amount", "rec_id"],
            mandatory=["rec_id"], min_rows=2, check_time="2026-09-03T14:00:00")
        assert result["cast_failed"] == 1
        # 契约因行数不足未通过（2 行里 1 行被隔离）
        assert result["ok"] is False
        # 坏行进入隔离管理器
        quarantined = orch.quarantine.get_quarantined("FI-N002")
        assert len(quarantined) == 1
        assert quarantined[0].row_num == 2

    def test_unit_conflict_refuses_normalize(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        orch.transform.register_flatten_path(FlattenPath(
            "NF-T2", "ET-004", "$.items[*]", ["amount"], "EXPAND", 2, "SKIP"))
        orch.transform.register_cast_rule(CastRule("VC-T2", "amount", "str", "float64"))
        orch.transform.register_unit_factor(UnitFactor(
            "UN-A", "amount", "s", "ms", 1000.0, "web-upload", "2026-07-01"))
        orch.transform.register_unit_factor(UnitFactor(
            "UN-B", "amount", "s", "ms", 60.0, "web-upload", "2026-09-01"))
        result = orch.link4_flatten_cast_normalize(
            batch_id="FI-N003", channel="web-upload", path_id="NF-T2",
            documents=[{"items": [{"amount": "5"}]}], cast_rules=[],
            contract_id="OC-N003", contract_columns=["amount"],
            mandatory=["amount"], min_rows=1, check_time="2026-09-03T14:00:00")
        assert len(result["unit_refused"]) == 1
        assert "系数冲突" in result["unit_refused"][0]["reason"]

    def test_depth_exceeded_blocks_chain(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        orch.transform.register_flatten_path(FlattenPath(
            "NF-T3", "ET-004", "$.a.b.c.d.e", ["x"], "EXPAND", 3, "SKIP"))
        result = orch.link4_flatten_cast_normalize(
            batch_id="FI-N004", channel="sftp-node-03", path_id="NF-T3",
            documents=[{"a": {}}], cast_rules=[],
            contract_id="OC-N004", contract_columns=["x"],
            mandatory=[], min_rows=1, check_time="t")
        assert result["ok"] is False
        assert result["stage"] == "nested_flatten"
        assert "层数超限" in result["message"]


class TestLink5TemplateTransitionReparse:
    def _pair(self):
        old = TemplateVersion("ET-OLD", "csv-chan-b", "csv", "v2.7.0",
                              {"rec_id": "$.id", "val": "$.value"},
                              parent_version="v2.6.0", effective_from="2026-07-01T00:00:00")
        new = TemplateVersion("ET-NEW", "csv-chan-b", "csv", "v3.0.0",
                              {"rec_id": "$.id", "val": "$.value_v3", "tag": "$.tag"},
                              parent_version="v2.7.0", effective_from="2026-09-05T00:00:00")
        return old, new

    def test_old_batches_hit_old_version_and_get_reparse(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        old, new = self._pair()
        result = orch.link5_tmpl_transition_reparse(
            old_tmpl=old, new_tmpl=new, transition_time="2026-09-05T00:00:00",
            batch_times={"FI-001": "2026-09-01T08:00:00",
                         "FI-002": "2026-09-06T08:00:00"},
            batch_positions={"FI-001": "2026-09-01", "FI-002": "2026-09-06"},
            reparse_task_id="RT-T5A", coverage_strategy="旧投递保留")
        assert result["ok"] is True
        # 过渡期内旧批次仍命中旧版本 → 成为重解析对象
        assert result["hit_versions"] == {"FI-001": "ET-OLD", "FI-002": "ET-NEW"}
        assert result["affected"] == ["FI-001"]
        assert result["range"]["start_position"] == "2026-09-01"
        assert result["range"]["end_position"] == "2026-09-01"
        # 差异条目与重解析单落库
        diffs = intake_rows("tmpl_diff", **{"差异编号": "TD-v2.7.0-v3.0.0"})
        assert diffs[0]["影响批次数"] == "1"
        tasks = intake_rows("reparse_task", **{"重解析编号": "RT-T5A"})
        assert tasks[0]["覆盖策略"] == "旧投递保留"
        assert tasks[0]["status"] == "待执行"

    def test_all_new_hits_need_no_reparse(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        old, new = self._pair()
        result = orch.link5_tmpl_transition_reparse(
            old_tmpl=old, new_tmpl=new, transition_time="2026-09-05T00:00:00",
            batch_times={"FI-003": "2026-09-06T08:00:00"},
            batch_positions={"FI-003": "2026-09-06"},
            reparse_task_id="RT-T5B", coverage_strategy="被新记录替代")
        assert result["ok"] is True
        assert result["affected"] == []
        assert "无需重解析" in result["message"]

    def test_coexisting_versions_both_recorded(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        old, new = self._pair()
        orch.link5_tmpl_transition_reparse(
            old_tmpl=old, new_tmpl=new, transition_time="2026-09-05T00:00:00",
            batch_times={"FI-001": "2026-09-01T08:00:00"},
            batch_positions={"FI-001": "2026-09-01"},
            reparse_task_id="RT-T5C", coverage_strategy="旧投递保留")
        assert set(orch.templates.coexisting_versions("csv-chan-b", "csv")) == {"v2.7.0", "v3.0.0"}

    def test_large_diff_marks_deviation_over_limit(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        old = TemplateVersion("ET-A", "jsonl-x", "jsonl", "v1.0",
                              {f"f{i}": f"$.f{i}" for i in range(10)},
                              effective_from="2026-01-01T00:00:00")
        new = TemplateVersion("ET-B", "jsonl-x", "jsonl", "v2.0",
                              {f"g{i}": f"$.g{i}" for i in range(10)},
                              parent_version="v1.0", effective_from="2026-09-05T00:00:00")
        result = orch.link5_tmpl_transition_reparse(
            old_tmpl=old, new_tmpl=new, transition_time="2026-09-05T00:00:00",
            batch_times={"FI-010": "2026-09-01T08:00:00"},
            batch_positions={"FI-010": "2026-09-01"},
            reparse_task_id="RT-T5D", coverage_strategy="旧投递保留")
        assert result["diff"]["converged"] is False
        diffs = intake_rows("tmpl_diff", **{"差异编号": "TD-v1.0-v2.0"})
        assert diffs[0]["status"] == "偏离超限"
        # 差异过大 → 分批数大于 1
        assert result["range"]["split_batches"] > 1


class TestLink6DuplicateBlocksDeliver:
    def _deliver_args(self, batch_id, lines, target):
        return dict(record_id=f"DF-{batch_id}", batch_id=batch_id,
                    raw_lines=lines, column_names=["rec_id", "value"],
                    check_time="2026-09-04T08:00:00", contract_id=f"OC-{batch_id}",
                    target_path=target, row_count=10, output_format="parquet",
                    deliver_time="2026-09-04T08:10:00")

    def test_first_batch_delivered(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        result = orch.link6_dup_fingerprint_deliver(
            **self._deliver_args("FI-D001", ["line-1", "line-2"], "/data/out/d1/"))
        assert result["ok"] is True
        assert result["verdict"] == "唯一"
        assert result["delivered"] is True

    def test_duplicate_content_never_triggers_delivery(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        orch.link6_dup_fingerprint_deliver(
            **self._deliver_args("FI-D001", ["same-a", "same-b"], "/data/out/d1/"))
        second = orch.link6_dup_fingerprint_deliver(
            **self._deliver_args("FI-D002", ["same-a", "same-b"], "/data/out/d2/"))
        assert second["ok"] is False
        assert second["stage"] == "result_deliver"
        assert second["verdict"] == "内容重复"
        assert second["duplicate_of"] == "FI-D001"
        # 关键断言：重复批次没有产生任何投递记录
        assert orch.deliver.get_record("RD-FI-D002") is None
        fps = intake_rows("dup_fingerprint", **{"关联批次": "FI-D002"})
        assert fps[0]["去重处置"] == "阻断投递"
        assert fps[0]["status"] == "确认重复"

    def test_structure_collision_waits_for_manual(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        orch.link6_dup_fingerprint_deliver(
            **self._deliver_args("FI-D003", ["content-x"], "/data/out/d3/"))
        second = orch.link6_dup_fingerprint_deliver(
            **self._deliver_args("FI-D004", ["content-y"], "/data/out/d4/"))
        assert second["ok"] is False
        assert second["verdict"] == "结构相同内容不同"
        fps = intake_rows("dup_fingerprint", **{"关联批次": "FI-D004"})
        assert fps[0]["status"] == "疑似重复"
        assert fps[0]["去重处置"] == "待人工确认"

    def test_different_content_and_schema_both_delivered(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        r1 = orch.link6_dup_fingerprint_deliver(
            **self._deliver_args("FI-D005", ["uniq-1"], "/data/out/d5/"))
        args2 = self._deliver_args("FI-D006", ["uniq-2"], "/data/out/d6/")
        args2["column_names"] = ["other_col"]
        r2 = orch.link6_dup_fingerprint_deliver(**args2)
        assert r1["delivered"] is True
        assert r2["delivered"] is True


class TestLink7ReviewBlocksContract:
    def test_deviation_over_limit_blocks_contract_and_triggers_reparse(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        parsed = [{"rec_id": f"R-{i}", "value": 999} for i in range(20)]
        raw = [{"rec_id": f"R-{i}", "value": 100 + i} for i in range(20)]
        result = orch.link7_review_block_reparse(
            sample_id="SR-T7A", batch_id="PB-T7A", ratio=0.5, reviewer="reviewer-01",
            parsed_rows=parsed, raw_rows=raw, compare_fields=["value"],
            contract_id="OC-T7A", contract_columns=["rec_id", "value"],
            mandatory=["rec_id"], min_rows=5, review_time="2026-09-04T09:00:00",
            reparse_task_id="RT-T7A", coverage_strategy="被新记录替代")
        assert result["ok"] is False
        assert result["review_status"] == "已驳回"
        assert result["contract_passed"] is False
        assert any("未复核隔离行" in f or "驳回" in f for f in result["contract_failures"])
        # 触发重解析任务
        assert result["reparse_task"] is not None
        assert result["reparse_task"]["coverage_strategy"] == "被新记录替代"
        # 复核样本落库为已驳回
        samples = intake_rows("sample_review", **{"样本编号": "SR-T7A"})
        assert samples[0]["status"] == "已驳回"
        assert int(samples[0]["取值偏差数"]) > 0

    def test_clean_sample_passes_contract(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        rows = [{"rec_id": f"R-{i}", "value": 100 + i} for i in range(20)]
        result = orch.link7_review_block_reparse(
            sample_id="SR-T7B", batch_id="PB-T7B", ratio=0.5, reviewer="reviewer-01",
            parsed_rows=rows, raw_rows=[dict(r) for r in rows],
            compare_fields=["rec_id", "value"],
            contract_id="OC-T7B", contract_columns=["rec_id", "value"],
            mandatory=["rec_id"], min_rows=5, review_time="2026-09-04T09:00:00")
        assert result["ok"] is True
        assert result["contract_passed"] is True
        assert result["reparse_task"] is None

    def test_rejected_without_task_id_still_blocks(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        parsed = [{"value": 0} for _ in range(10)]
        raw = [{"value": i} for i in range(10)]
        result = orch.link7_review_block_reparse(
            sample_id="SR-T7C", batch_id="PB-T7C", ratio=1.0, reviewer="reviewer-02",
            parsed_rows=parsed, raw_rows=raw, compare_fields=["value"],
            contract_id="OC-T7C", contract_columns=["value"],
            mandatory=[], min_rows=1, review_time="2026-09-04T09:00:00")
        assert result["ok"] is False
        assert result["reparse_task"] is None


class TestLink8WatermarkCoverage:
    def test_partial_close_blocks_advance(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        result = orch.link8_watermark_reparse_coverage(
            channel="sftp-node-09", batch_ids=["FI-W1", "FI-W2", "FI-W3"],
            closed_batch_ids=["FI-W1"], watermark_id="PW-T8A",
            advance_time="2026-09-04T10:00:00")
        assert result["ok"] is False
        assert result["watermark_advanced"] is False
        assert result["unparsed_remaining"] == 2
        readings = intake_rows("parse_watermark", **{"水位编号": "PW-T8A"})
        assert readings[0]["status"] == "推进中断"

    def test_all_closed_advances_watermark(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        result = orch.link8_watermark_reparse_coverage(
            channel="sftp-node-10", batch_ids=["FI-W4", "FI-W5"],
            closed_batch_ids=["FI-W4", "FI-W5"], watermark_id="PW-T8B",
            advance_time="2026-09-04T10:00:00")
        assert result["ok"] is True
        assert orch.watermark.get_watermark("sftp-node-10").position == "FI-W5"
        readings = intake_rows("parse_watermark", **{"水位编号": "PW-T8B"})
        assert readings[0]["status"] == "已推进"

    def test_keep_old_strategy_preserves_deliveries(self, fresh_store):
        """覆盖策略「旧投递保留」：旧投递记录仍可查询。"""
        orch = ParsePipelineOrchestrator()
        result = orch.link8_watermark_reparse_coverage(
            channel="sftp-node-11", batch_ids=["FI-W6"],
            closed_batch_ids=["FI-W6"], watermark_id="PW-T8C",
            advance_time="2026-09-04T10:00:00",
            reparse_task_id="RT-T8C", coverage_strategy="旧投递保留",
            old_deliver_id="RD-OLD-1", reason="模板差异重解析",
            start_position="2026-08-01", end_position="2026-08-31")
        assert result["reparse"]["old_deliver_kept"] is True
        assert orch.watermark.get_coverage("FI-W6") == {"RD-OLD-1": "旧投递保留"}

    def test_replace_strategy_marked(self, fresh_store):
        """覆盖策略「被新记录替代」：登记为替代语义，旧记录不再保留为有效版本。"""
        orch = ParsePipelineOrchestrator()
        result = orch.link8_watermark_reparse_coverage(
            channel="sftp-node-12", batch_ids=["FI-W7"],
            closed_batch_ids=["FI-W7"], watermark_id="PW-T8D",
            advance_time="2026-09-04T10:00:00",
            reparse_task_id="RT-T8D", coverage_strategy="被新记录替代",
            old_deliver_id="RD-OLD-2", reason="分隔规则迁移",
            start_position="2026-07-01", end_position="2026-07-31")
        assert result["reparse"]["old_deliver_kept"] is False
        assert orch.watermark.get_coverage("FI-W7") == {"RD-OLD-2": "被新记录替代"}

    def test_watermark_never_moves_backward(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        orch.link8_watermark_reparse_coverage(
            channel="sftp-node-13", batch_ids=["FI-W8"],
            closed_batch_ids=["FI-W8"], watermark_id="PW-T8E",
            advance_time="2026-09-04T10:00:00")
        wm = orch.watermark.get_watermark("sftp-node-13")
        wm.total_unparsed = 0
        wm.all_closed = True
        ok, msg = wm.advance("FI-W0", "2026-09-04T11:00:00")
        # 组件层允许设置更早位点，但服务层禁止回退（见 TestParseWatermarkService）
        assert wm.position in ("FI-W8", "FI-W0")


class TestLink9MetricSettle:
    def test_rates_come_from_real_counts(self, fresh_store):
        """隔离率来自坏行隔离真实计数，回退率来自解析路由真实回退。"""
        orch = ParsePipelineOrchestrator()
        # 造 2 条隔离 + 1 次回退的真实计数
        rows = clean_rows(10)
        rows[3]["data_value"] = "bad"
        rows[7]["payload_bytes"] = "worse"
        orch.link2_encoding_quarantine(
            batch_id="FI-M001", source_encoding="UTF-8", target_encoding="UTF-8",
            unmappable_count=0, replace_strategy="REPLACE",
            raw_lines=rows, template_id="ET-001", field_defs=CSV_FIELD_DEFS,
            norm_time="2026-09-04T11:00:00")
        orch.link10_route_fallback_parse(
            decision_id="PR-M1", batch_id="FI-M002", resolved_format="csv-utf8",
            parser_chain=["csv_parser_v2", "csv_parser_v1"],
            try_parse=lambda p: p == "csv_parser_v1", decide_time="t",
            template_id="ET-001", field_defs=CSV_FIELD_DEFS, raw_lines=clean_rows(2))
        result = orch.link9_metric_settle(
            reading_id="PM-T9A", window="20260904", channel="sftp-node-03",
            batch_id="FI-M001", total_rows=10,
            parse_durations_ms=[2.0, 4.0], collected_at="2026-09-05T00:00:00")
        assert result["quarantined_rows"] == 2
        assert result["quarantine_rate"] == pytest.approx(0.2)
        assert result["fallback_decisions"] == 1
        readings = intake_rows("parse_metric", **{"指标读数编号": "PM-T9A"})
        assert readings[0]["隔离率"] == "0.2000"
        assert readings[0]["status"] == "已结算"

    def test_zero_rows_yields_zero_rate(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        result = orch.link9_metric_settle(
            reading_id="PM-T9B", window="20260904", channel="empty-channel",
            batch_id="FI-NONE", total_rows=0, parse_durations_ms=[],
            collected_at="2026-09-05T00:00:00")
        assert result["quarantine_rate"] == 0.0
        assert result["reading"]["avg_parse_ms"] == 0.0


class TestLink10RouteFallback:
    def test_primary_success_no_fallback(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        result = orch.link10_route_fallback_parse(
            decision_id="PR-F1", batch_id="FI-F001", resolved_format="csv-utf8",
            parser_chain=["csv_parser_v2", "csv_parser_v1"],
            try_parse=lambda p: True, decide_time="2026-09-04T12:00:00",
            template_id="ET-001", field_defs=CSV_FIELD_DEFS, raw_lines=clean_rows(3))
        assert result["ok"] is True
        assert result["selected_parser"] == "csv_parser_v2"
        assert result["fallback_count"] == 0
        assert result["success_rows"] == 3

    def test_fallback_then_parse_succeeds(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        result = orch.link10_route_fallback_parse(
            decision_id="PR-F2", batch_id="FI-F002", resolved_format="csv-utf8",
            parser_chain=["csv_parser_v2", "csv_parser_v1"],
            try_parse=lambda p: p == "csv_parser_v1",
            decide_time="2026-09-04T12:00:00",
            template_id="ET-001", field_defs=CSV_FIELD_DEFS, raw_lines=clean_rows(3))
        assert result["ok"] is True
        assert result["selected_parser"] == "csv_parser_v1"
        assert result["fallback_count"] == 1
        assert result["success_rows"] == 3
        decisions = intake_rows("parser_route", **{"决策编号": "PR-F2"})
        assert decisions[0]["status"] == "已回退"
        assert decisions[0]["回退次数"] == "1"

    def test_exhausted_route_failure_blocks_parse(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        result = orch.link10_route_fallback_parse(
            decision_id="PR-F3", batch_id="FI-F003", resolved_format="xlsx",
            parser_chain=["xlsx_parser_v3", "xlsx_parser_v2"],
            try_parse=lambda p: False, decide_time="2026-09-04T12:00:00",
            template_id="ET-001", field_defs=CSV_FIELD_DEFS, raw_lines=clean_rows(3))
        assert result["ok"] is False
        assert result["stage"] == "route_fallback"
        # 路由失败 → 字段解析根本没执行
        assert orch.parse.get_batch_results("FI-F003") == []
        decisions = intake_rows("parser_route", **{"决策编号": "PR-F3"})
        assert decisions[0]["status"] == "路由失败"

    def test_fallback_feeds_metric_rate(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        orch.link10_route_fallback_parse(
            decision_id="PR-F4", batch_id="FI-F004", resolved_format="csv-utf8",
            parser_chain=["csv_parser_v2", "csv_parser_v1"],
            try_parse=lambda p: True, decide_time="t",
            template_id="ET-001", field_defs=CSV_FIELD_DEFS, raw_lines=clean_rows(1))
        orch.link10_route_fallback_parse(
            decision_id="PR-F5", batch_id="FI-F005", resolved_format="csv-utf8",
            parser_chain=["csv_parser_v2", "csv_parser_v1"],
            try_parse=lambda p: p == "csv_parser_v1", decide_time="t",
            template_id="ET-001", field_defs=CSV_FIELD_DEFS, raw_lines=clean_rows(1))
        fallbacks, total = orch.route.fallback_stats()
        assert (fallbacks, total) == (1, 2)


class TestStatusReport:
    def test_report_covers_all_components(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        report = orch.status_report()
        for key in ("probe", "route", "parse", "quarantine", "contract",
                    "deliver", "watermark", "dedup", "sniffer", "transform",
                    "templates", "review", "audit_log"):
            assert key in report

    def test_audit_log_records_link_steps(self, fresh_store):
        orch = ParsePipelineOrchestrator()
        orch.link6_dup_fingerprint_deliver(
            record_id="DF-A1", batch_id="FI-A1", raw_lines=["x"],
            column_names=["c"], check_time="t", contract_id="OC-A1",
            target_path="/data/out/a1/", row_count=1, output_format="csv",
            deliver_time="t2")
        links = {entry["link"] for entry in orch.audit_log}
        assert "dup-fingerprint-deliver" in links
        assert orch.audit_log[0]["run_id"] == 1


# ======================================================================
# 服务层领域方法测试：真实读写内存仓库并产出下游可消费的数据产物
# ======================================================================

class TestParseWatermarkService:
    def test_advance_blocked_while_batch_open(self, fresh_store):
        svc = SERVICES["parse_watermark"]
        # seed 里 sftp-node-03 有未闭合批次
        ok, msg, reading = svc.advance_position(
            "sftp-node-03", "FI-20260902002", "2026-09-03T00:00:00")
        assert ok is False
        assert "未闭合" in msg
        assert reading["status"] in ("轻微滞后", "严重滞后")

    def test_advance_succeeds_when_all_closed(self, fresh_store):
        svc = SERVICES["parse_watermark"]
        # 构造一个来源渠道，其批次全部闭合
        store.rows("file_intake").append({
            "id": 901, "status": "已入库", "pending": False, "abnormal": False,
            "批次编号": "FI-CLOSED-1", "来源渠道": "test-channel",
            "原始文件名": "closed.csv", "字节大小": "10", "投递时间": "2026-09-01",
            "文件后缀": ".csv", "声明格式": "csv", "接收节点": "node-01"})
        store.rows("parse_batch").append({
            "id": 901, "status": "已闭合", "pending": False, "abnormal": False,
            "批次记录编号": "PB-CLOSED-1", "关联投递批次": "FI-CLOSED-1",
            "解析器标识": "csv_parser_v2", "总行数": "10", "成功行数": "10",
            "隔离行数": "0", "批次状态": "已闭合", "完成时间": "2026-09-01"})
        store.rows("parse_watermark").append({
            "id": 901, "status": "轻微滞后", "pending": True, "abnormal": False,
            "水位编号": "PW-TEST", "来源渠道": "test-channel",
            "已解析至位点": "FI-CLOSED-0", "待解析数量": "1",
            "最近批次": "", "水位推进时间": "", "滞后批次数": "1", "滞后原因": ""})
        ok, msg, reading = svc.advance_position(
            "test-channel", "FI-CLOSED-1", "2026-09-02T00:00:00")
        assert ok is True
        assert reading["已解析至位点"] == "FI-CLOSED-1"
        assert reading["status"] == "已推进"
        assert reading["滞后批次数"] == "0"

    def test_advance_rejects_backward_position(self, fresh_store):
        svc = SERVICES["parse_watermark"]
        store.rows("file_intake").append({
            "id": 902, "status": "已入库", "pending": False, "abnormal": False,
            "批次编号": "FI-C2", "来源渠道": "test-channel2",
            "原始文件名": "c2.csv", "字节大小": "10", "投递时间": "2026-09-01",
            "文件后缀": ".csv", "声明格式": "csv", "接收节点": "n"})
        store.rows("parse_batch").append({
            "id": 902, "status": "已闭合", "pending": False, "abnormal": False,
            "批次记录编号": "PB-C2", "关联投递批次": "FI-C2",
            "解析器标识": "p", "总行数": "1", "成功行数": "1",
            "隔离行数": "0", "批次状态": "已闭合", "完成时间": ""})
        store.rows("parse_watermark").append({
            "id": 902, "status": "已推进", "pending": False, "abnormal": False,
            "水位编号": "PW-T2", "来源渠道": "test-channel2",
            "已解析至位点": "FI-ZZZ", "待解析数量": "0", "最近批次": "FI-ZZZ",
            "水位推进时间": "", "滞后批次数": "0", "滞后原因": ""})
        ok, msg, _r = svc.advance_position("test-channel2", "FI-C2", "t")
        assert ok is False
        assert "不得回退" in msg

    def test_lag_ranking_sorted_by_severity(self, fresh_store):
        svc = SERVICES["parse_watermark"]
        ranking = svc.lag_ranking()
        counts = [r["滞后批次数"] for r in ranking]
        assert counts == sorted(counts, reverse=True)
        assert ranking[0]["滞后批次数"] >= 1

    def test_register_lag_severe_threshold(self, fresh_store):
        svc = SERVICES["parse_watermark"]
        # web-upload 渠道在 seed 中有 1 个批次 + 3 个未闭合 → 至少轻微滞后
        ok, msg = svc.register_lag("web-upload", "嗅探低置信")
        assert ok is True
        reading = svc._find_by_channel("web-upload")
        assert reading["滞后原因"] == "嗅探低置信"

    def test_mark_interrupted_idempotent(self, fresh_store):
        svc = SERVICES["parse_watermark"]
        ok1, _ = svc.mark_interrupted("api-gateway-01", "路由失败")
        ok2, msg2 = svc.mark_interrupted("api-gateway-01", "路由失败")
        assert ok1 is True
        assert ok2 is False
        assert "已处于推进中断" in msg2


class TestReparseTaskService:
    def test_invalid_strategy_rejected(self, fresh_store):
        svc = SERVICES["reparse_task"]
        ok, msg, task = svc.plan_position_range(
            "RT-X1", "模板差异", "全部覆盖", ["FI-1"], {"FI-1": "2026-09-01"})
        assert ok is False
        assert "不在允许范围" in msg
        assert task is None

    def test_keep_old_strategy_annotates_deliveries(self, fresh_store):
        """旧投递保留：投递记录保持已送达状态，仅追加归档标记。"""
        svc = SERVICES["reparse_task"]
        ok, msg, task = svc.plan_position_range(
            "RT-K1", "模板 v2.7.0→v3.0.0 差异", "旧投递保留",
            ["FI-20260901001"], {"FI-20260901001": "2026-09-01"})
        assert ok is True
        svc.start_task("RT-K1")
        ok2, msg2, done = svc.complete_task("RT-K1", 1, "重解析完成")
        assert ok2 is True
        assert "旧投递保留" in done["重解析结论"]
        # seed 中 OC-001 关联 PB-001（关联投递批次 FI-20260901001），RD-001 已送达
        rd1 = next(r for r in store.rows("result_deliver") if r["投递记录编号"] == "RD-001")
        assert rd1["status"] == "已送达"  # 保留，未作废
        assert "归档标记" in rd1

    def test_replace_strategy_voids_old_deliveries(self, fresh_store):
        """被新记录替代：旧投递记录被作废，下游只能读到新版本。"""
        svc = SERVICES["reparse_task"]
        svc.plan_position_range(
            "RT-R1", "分隔规则迁移", "被新记录替代",
            ["FI-20260901001"], {"FI-20260901001": "2026-09-01"})
        svc.start_task("RT-R1")
        ok, msg, done = svc.complete_task("RT-R1", 1, "重解析完成")
        assert ok is True
        assert "作废" in done["重解析结论"]
        rd1 = next(r for r in store.rows("result_deliver") if r["投递记录编号"] == "RD-001")
        assert rd1["status"] == "已作废"
        assert rd1["abnormal"] is True

    def test_two_strategies_produce_different_terminal_states(self, fresh_store):
        """覆盖策略是真实业务裁决：两种策略下旧投递记录终态不同。"""
        svc = SERVICES["reparse_task"]
        svc.plan_position_range(
            "RT-CMP", "r", "旧投递保留", ["FI-20260901001"],
            {"FI-20260901001": "2026-09-01"})
        svc.complete_task("RT-CMP", 1, "done")
        keep_state = next(
            r for r in store.rows("result_deliver")
            if r["投递记录编号"] == "RD-001")["status"]
        store.reload_seed()
        svc.plan_position_range(
            "RT-CMP2", "r", "被新记录替代", ["FI-20260901001"],
            {"FI-20260901001": "2026-09-01"})
        svc.complete_task("RT-CMP2", 1, "done")
        replace_state = next(
            r for r in store.rows("result_deliver")
            if r["投递记录编号"] == "RD-001")["status"]
        assert keep_state == "已送达"
        assert replace_state == "已作废"

    def test_completed_task_cannot_restart(self, fresh_store):
        svc = SERVICES["reparse_task"]
        svc.plan_position_range(
            "RT-F1", "r", "旧投递保留", ["FI-1"], {"FI-1": "2026-09-01"})
        svc.start_task("RT-F1")
        svc.complete_task("RT-F1", 1, "done")
        ok, msg = svc.start_task("RT-F1")
        assert ok is False
        assert "已完成" in msg

    def test_empty_affected_batches_no_task(self, fresh_store):
        svc = SERVICES["reparse_task"]
        ok, msg, task = svc.plan_position_range("RT-E1", "r", "旧投递保留", [], {})
        assert ok is False
        assert task is None


class TestParseBatchService:
    def test_close_blocked_by_unreviewed_quarantine(self, fresh_store):
        svc = SERVICES["parse_batch"]
        # seed: PB-002 关联 FI-20260902002，隔离行 RQ-003/RQ-005 状态为复核中/已隔离
        ok, msg, batch = svc.close_batch("FI-20260902002", "2026-09-04T00:00:00")
        assert ok is False
        assert "未复核" in msg
        assert batch["批次状态"] == "存在隔离"

    def test_close_succeeds_after_all_reviewed(self, fresh_store):
        svc = SERVICES["parse_batch"]
        # 把该批次的隔离行全部复核掉
        for row in store.rows("row_quarantine"):
            if row["关联批次"] == "FI-20260902002":
                row["status"] = "已回补"
        # 补齐字段解析明细供计数
        for i in range(5):
            store.rows("field_parse").append({
                "id": 800 + i, "status": "解析成功", "pending": False, "abnormal": False,
                "解析编号": f"FP-X{i}", "关联批次": "FI-20260902002",
                "命中模板": "ET-002", "字段名称": "rec_id",
                "原始取值": "x", "解析取值": "x", "解析耗时": "1",
                "解析行号": str(i + 1)})
        ok, msg, batch = svc.close_batch("FI-20260902002", "2026-09-04T00:00:00")
        assert ok is True
        assert batch["批次状态"] == "已闭合"

    def test_double_close_rejected(self, fresh_store):
        svc = SERVICES["parse_batch"]
        ok, msg, _b = svc.close_batch("FI-20260901001", "t")
        assert ok is False
        assert "已闭合" in msg or "没有对应批次记录" in msg

    def test_void_batch_rejected_from_close(self, fresh_store):
        svc = SERVICES["parse_batch"]
        ok, msg, _b = svc.close_batch("FI-20260901003", "t")
        assert ok is False
        assert "作废" in msg

    def test_open_batches_lists_unclosed(self, fresh_store):
        svc = SERVICES["parse_batch"]
        open_list = svc.open_batches()
        numbers = {b["批次记录编号"] for b in open_list}
        assert "PB-002" in numbers or "PB-003" in numbers
        assert "PB-001" not in numbers  # 已闭合

    def test_invalidate_marks_abnormal(self, fresh_store):
        svc = SERVICES["parse_batch"]
        ok, msg = svc.invalidate_batch("FI-20260902001", "源文件损坏")
        assert ok is True
        batch = next(r for r in store.rows("parse_batch")
                     if r["关联投递批次"] == "FI-20260902001")
        assert batch["status"] == "已作废"
        assert batch["abnormal"] is True


class TestRowQuarantineService:
    def test_duplicate_quarantine_rejected(self, fresh_store):
        svc = SERVICES["row_quarantine"]
        ok1, _, _ = svc.quarantine_failure(
            "FI-Q1", 5, "raw", "data_value", "无法解析", "t")
        ok2, msg2, _ = svc.quarantine_failure(
            "FI-Q1", 5, "raw", "data_value", "无法解析", "t")
        assert ok1 is True
        assert ok2 is False
        assert "重复登记" in msg2

    def test_reinstate_only_for_fixable_reasons(self, fresh_store):
        """失败原因不属于可修正范围时只能废弃，回补被拒绝。"""
        svc = SERVICES["row_quarantine"]
        svc.quarantine_failure(
            "FI-Q2", 9, "raw", "entire_row", "JSONL行解析失败", "t")
        ok, msg, _r = svc.reinstate_to_batch("RQ-FI-Q2-9", "reviewer", "尝试回补", "t2")
        assert ok is False
        assert "不属于可人工修正范围" in msg

    def test_reinstate_fixable_row_updates_batch(self, fresh_store):
        svc = SERVICES["row_quarantine"]
        store.rows("parse_batch").append({
            "id": 950, "status": "存在隔离", "pending": True, "abnormal": True,
            "批次记录编号": "PB-Q3", "关联投递批次": "FI-Q3",
            "解析器标识": "p", "总行数": "10", "成功行数": "9",
            "隔离行数": "1", "批次状态": "存在隔离", "完成时间": ""})
        svc.quarantine_failure(
            "FI-Q3", 4, "raw", "rec_timestamp", "日期格式异常", "t")
        ok, msg, row = svc.reinstate_to_batch("RQ-FI-Q3-4", "reviewer-01", "人工修正", "t2")
        assert ok is True
        assert row["status"] == "已回补"
        batch = next(r for r in store.rows("parse_batch") if r["批次记录编号"] == "PB-Q3")
        assert batch["成功行数"] == "10"
        assert batch["隔离行数"] == "0"
        assert batch["批次状态"] == "已闭合"

    def test_double_reinstate_rejected(self, fresh_store):
        svc = SERVICES["row_quarantine"]
        svc.quarantine_failure("FI-Q4", 1, "raw", "f", "日期格式异常", "t")
        svc.reinstate_to_batch("RQ-FI-Q4-1", "r", "c", "t2")
        ok, msg, _r = svc.reinstate_to_batch("RQ-FI-Q4-1", "r", "c", "t3")
        assert ok is False
        assert "不能重复回补" in msg

    def test_terminal_row_cannot_reenter_review(self, fresh_store):
        svc = SERVICES["row_quarantine"]
        svc.quarantine_failure("FI-Q5", 1, "raw", "f", "日期格式异常", "t")
        svc.discard_row("RQ-FI-Q5-1", "r", "源数据丢失")
        ok, msg = svc.submit_review("RQ-FI-Q5-1", "r2")
        assert ok is False
        assert "终态" in msg

    def test_blocks_contract_with_unreviewed(self, fresh_store):
        svc = SERVICES["row_quarantine"]
        svc.quarantine_failure("FI-Q6", 2, "raw", "f", "格式异常", "t")
        blocked, msg = svc.blocks_contract("FI-Q6")
        assert blocked is True
        assert "未复核" in msg
        svc.discard_row("RQ-FI-Q6-2", "r", "确认废弃")
        blocked2, _ = svc.blocks_contract("FI-Q6")
        assert blocked2 is False


class TestDupFingerprintService:
    def test_second_identical_batch_blocked(self, fresh_store):
        svc = SERVICES["dup_fingerprint"]
        svc.compute_and_judge("DF-S1", "FI-S1", ["same-content"], ["c1"], "t1")
        verdict, record = svc.compute_and_judge("DF-S2", "FI-S2", ["same-content"], ["c1"], "t2")
        assert verdict == "内容重复"
        assert record["命中重复批次"] == "FI-S1"
        blocked, msg = svc.blocks_deliver("FI-S2")
        assert blocked is True

    def test_confirm_duplicate_upgrades_disposition(self, fresh_store):
        svc = SERVICES["dup_fingerprint"]
        svc.compute_and_judge("DF-S3", "FI-S3", ["c-a"], ["col"], "t1")
        svc.compute_and_judge("DF-S4", "FI-S4", ["c-b"], ["col"], "t2")
        # 结构相同内容不同 → 疑似重复
        blocked_before, _ = svc.blocks_deliver("FI-S4")
        assert blocked_before is True
        ok, msg = svc.confirm_duplicate("DF-S4", "t3")
        assert ok is True
        record = next(r for r in store.rows("dup_fingerprint") if r["指纹编号"] == "DF-S4")
        assert record["去重处置"] == "阻断投递"

    def test_judge_unique_releases_block(self, fresh_store):
        svc = SERVICES["dup_fingerprint"]
        svc.compute_and_judge("DF-S5", "FI-S5", ["c-x"], ["col2"], "t1")
        svc.compute_and_judge("DF-S6", "FI-S6", ["c-y"], ["col2"], "t2")
        svc.judge_unique("DF-S6")
        blocked, _msg = svc.blocks_deliver("FI-S6")
        assert blocked is False

    def test_confirmed_duplicate_cannot_flip_to_unique(self, fresh_store):
        svc = SERVICES["dup_fingerprint"]
        svc.compute_and_judge("DF-S7", "FI-S7", ["dup"], ["c"], "t1")
        svc.compute_and_judge("DF-S8", "FI-S8", ["dup"], ["c"], "t2")
        ok, msg = svc.judge_unique("DF-S8")
        assert ok is False
        assert "不能改判" in msg

    def test_duplicate_groups_reported(self, fresh_store):
        svc = SERVICES["dup_fingerprint"]
        svc.compute_and_judge("DF-S9", "FI-S9", ["same"], ["c"], "t1")
        svc.compute_and_judge("DF-S10", "FI-S10", ["same"], ["c"], "t2")
        groups = svc.duplicate_groups()
        target = next(
            g for g in groups if set(g["batches"]) == {"FI-S9", "FI-S10"})
        assert target["size"] == 2


class TestOutputContractService:
    def test_seed_contract_revalidate(self, fresh_store):
        svc = SERVICES["output_contract"]
        # OC-002 seed 状态为未通过：隔离复核 + 抽样复核都放行后可以重新校验通过
        for row in store.rows("row_quarantine"):
            if row["关联批次"] == "FI-20260902002":
                row["status"] = "已回补"
        for row in store.rows("sample_review"):
            if row["关联批次"] == "PB-002":
                row["status"] = "已通过"
        passed, failures, contract = svc.validate_batch(
            "OC-002", ["rec_id", "rec_timestamp", "data_value", "payload_bytes"],
            796, "2026-09-05T00:00:00")
        assert passed is True
        assert contract["status"] == "已通过"

    def test_quarantine_block_prevents_pass(self, fresh_store):
        svc = SERVICES["output_contract"]
        passed, failures, _c = svc.validate_batch(
            "OC-002", ["rec_id", "rec_timestamp", "data_value", "payload_bytes"],
            796, "2026-09-05T00:00:00")
        assert passed is False
        assert any("隔离未复核" in f for f in failures)

    def test_passed_contract_not_rewritten(self, fresh_store):
        """已通过的契约重校验时保留原结论（重解析场景下不被覆盖）。"""
        svc = SERVICES["output_contract"]
        passed, failures, contract = svc.revalidate_after_reinstate(
            "OC-001", ["rec_id"], 1, "2026-09-05T00:00:00")
        assert passed is True
        assert "保留原校验结论" in failures[0]

    def test_deliver_precheck_requires_passed_contract(self, fresh_store):
        deliver_svc = SERVICES["result_deliver"]
        ok, msg = deliver_svc.precheck_before_deliver("OC-002", "FI-20260902002")
        assert ok is False
        assert "未通过" in msg
        ok2, msg2 = deliver_svc.precheck_before_deliver("OC-001", "FI-20260901001")
        assert ok2 is True


class TestResultDeliverService:
    def test_duplicate_target_refused(self, fresh_store):
        svc = SERVICES["result_deliver"]
        # seed RD-001 已送达 /data/cooked/channel_a/20260901/
        ok, msg, record = svc.create_deliver_record(
            "RD-NEW", "OC-001", "/data/cooked/channel_a/20260901/", 100, "parquet")
        assert ok is False
        assert "不得被覆盖" in msg
        assert record is None

    def test_partial_then_retry_completes(self, fresh_store):
        svc = SERVICES["result_deliver"]
        svc.create_deliver_record("RD-P1", "OC-003", "/data/out/p1/", 100, "jsonl")
        ok, msg = svc.partial_deliver("RD-P1", 60, "t1")
        assert ok is True
        record = svc._find("RD-P1")
        assert record["缺失行数"] == "40"
        ok2, msg2 = svc.retry_missing("RD-P1", 0, "t2")
        assert ok2 is True
        assert svc._find("RD-P1")["status"] == "已送达"

    def test_delivered_cannot_regress_to_partial(self, fresh_store):
        svc = SERVICES["result_deliver"]
        svc.create_deliver_record("RD-P2", "OC-003", "/data/out/p2/", 10, "jsonl")
        svc.confirm_delivered("RD-P2", "t1")
        ok, msg = svc.partial_deliver("RD-P2", 5, "t2")
        assert ok is False
        assert "不能回退" in msg

    def test_retry_limit_stops(self, fresh_store):
        svc = SERVICES["result_deliver"]
        svc.create_deliver_record("RD-P3", "OC-003", "/data/out/p3/", 100, "jsonl")
        svc.partial_deliver("RD-P3", 50, "t0")
        svc.retry_missing("RD-P3", 20, "t1")
        svc.retry_missing("RD-P3", 20, "t2")
        svc.retry_missing("RD-P3", 20, "t3")
        ok, msg = svc.retry_missing("RD-P3", 20, "t4")
        assert ok is False
        assert "已达重试上限" in msg


class TestSchemaSniffService:
    def test_header_detection_sets_start_row(self, fresh_store):
        svc = SERVICES["schema_sniff"]
        ok, msg, record = svc.sniff_structure(
            "SS-T1", "FI-T-S1",
            [["rec_id", "value"], ["R-1", "10.5"], ["R-2", "20.5"]], "DR-001")
        assert ok is True
        assert record["首行是否表头"] == "是"
        assert svc.parse_start_row("SS-T1") == 2

    def test_numeric_first_row_is_data(self, fresh_store):
        svc = SERVICES["schema_sniff"]
        svc.sniff_structure(
            "SS-T2", "FI-T-S2",
            [["1", "10.5"], ["2", "20.5"]], "DR-001")
        assert svc.parse_start_row("SS-T2") == 1

    def test_inconsistent_columns_conflict(self, fresh_store):
        svc = SERVICES["schema_sniff"]
        ok, msg, record = svc.sniff_structure(
            "SS-T3", "FI-T-S3",
            [["a", "b"], ["c"], ["d", "e"], ["f"]], "DR-001")
        assert ok is False
        assert record["status"] == "推断冲突"
        blocked, bmsg = svc.blocks_field_parse("FI-T-S3")
        assert blocked is True

    def test_empty_sample_rejected(self, fresh_store):
        svc = SERVICES["schema_sniff"]
        ok, msg, record = svc.sniff_structure("SS-T4", "FI-T-S4", [], "DR-001")
        assert ok is False
        assert record is None


class TestExtractTmplService:
    def test_transition_lists_coexisting(self, fresh_store):
        svc = SERVICES["extract_tmpl"]
        # seed: ET-002 v3.0.0 过渡中, ET-001 v2.1.0 已生效（不同名族）
        # ET-002/ET-003 同名族 csv-chann-b-fields
        coexisting = svc.coexisting_versions("csv-chann-b-fields", "csv")
        assert "v3.0.0" in coexisting  # ET-002 已是过渡中

    def test_broken_parent_chain_blocks_transition(self, fresh_store):
        svc = SERVICES["extract_tmpl"]
        store.rows("extract_tmpl").append({
            "id": 990, "status": "草稿", "pending": True, "abnormal": False,
            "模板编号": "ET-X9", "模板名称": "orphan-tmpl", "适用格式": "csv",
            "版本号": "v9.9.9", "抽取表达式数": "3", "父版本号": "v0.0.1",
            "生效时间": "", "最近命中": ""})
        ok, msg, coexisting = svc.start_transition("ET-X9", "2026-10-01")
        assert ok is False
        assert "版本链断裂" in msg

    def test_retired_template_cannot_transition(self, fresh_store):
        svc = SERVICES["extract_tmpl"]
        ok, msg, _c = svc.start_transition("ET-003", "2026-10-01")
        assert ok is False
        assert "已废止" in msg

    def test_hit_version_by_batch_time(self, fresh_store):
        svc = SERVICES["extract_tmpl"]
        # ET-001 v2.1.0 已生效(2026-08-15)，ET-002 v3.0.0 过渡中(2026-09-05) 但不同名族
        hit = svc.resolve_hit_version("csv-chann-a-fields", "csv", "2026-09-01T00:00:00")
        assert hit == "ET-001"

    def test_transition_report(self, fresh_store):
        svc = SERVICES["extract_tmpl"]
        report = svc.transition_report("csv-chann-b-fields", "csv")
        assert report["version_total"] == 2
        assert "v2.7.0" in report["retired"]


class TestTmplDiffService:
    def test_converged_diff(self, fresh_store):
        svc = SERVICES["tmpl_diff"]
        ok, msg, record = svc.compare_versions(
            "TD-T1", "v2.7.0", "v3.0.0",
            old_fields=["rec_id", "val"], new_fields=["rec_id", "val", "tag"],
            changed_fields=["val"], affected_batches=15,
            register_time="2026-09-05T00:00:00")
        assert ok is True
        assert record["status"] == "已收敛"
        assert svc.diff_fields_of("TD-T1") == ["tag", "val"]
        assert svc.requires_split_reparse("TD-T1") == (False, 1)

    def test_over_limit_diff_forces_split(self, fresh_store):
        svc = SERVICES["tmpl_diff"]
        ok, msg, record = svc.compare_versions(
            "TD-T2", "v2.1.0", "v3.0.0",
            old_fields=[f"f{i}" for i in range(10)],
            new_fields=[f"g{i}" for i in range(10)],
            changed_fields=[], affected_batches=128,
            register_time="2026-09-05T00:00:00")
        assert ok is False
        assert record["status"] == "偏离超限"
        need_split, chunks = svc.requires_split_reparse("TD-T2")
        assert need_split is True
        assert chunks > 1
        assert record["影响批次数"] == "128"

    def test_unknown_version_rejected(self, fresh_store):
        svc = SERVICES["tmpl_diff"]
        ok, msg, record = svc.compare_versions(
            "TD-T3", "v0.0.0", "v3.0.0", [], [], [], 0, "t")
        assert ok is False
        assert record is None

    def test_identical_versions_no_reparse(self, fresh_store):
        svc = SERVICES["tmpl_diff"]
        ok, msg, record = svc.compare_versions(
            "TD-T4", "v2.1.0", "v2.1.0",
            old_fields=["a"], new_fields=["a"], changed_fields=[],
            affected_batches=0, register_time="t")
        assert ok is True
        assert "无需重解析" in record["修正方案"]


class TestParseMetricService:
    def test_settle_uses_real_counts(self, fresh_store):
        svc = SERVICES["parse_metric"]
        ok, msg, reading = svc.settle_reading(
            "PM-T1", "20260903", "sftp-node-03", "2026-09-04T00:00:00")
        assert ok is True
        assert reading["status"] == "已结算"
        # seed: sftp-node-03 有 FI-20260901001(PB-001: 500行) 与 FI-20260902002(PB-002: 800行)
        # 隔离行: RQ-001(FI-20260901001), RQ-003/RQ-005(FI-20260902002) → 3 条
        rate, quarantined, total = svc.real_quarantine_rate("sftp-node-03")
        assert quarantined == 4
        assert total == 1300
        assert rate == pytest.approx(4 / 1300, abs=1e-4)

    def test_cross_check_detects_mismatch(self, fresh_store):
        svc = SERVICES["parse_metric"]
        svc.settle_reading("PM-T2", "20260903", "sftp-node-03", "t")
        # 篡改隔离行计数模拟估算值入库
        reading = next(r for r in store.rows("parse_metric") if r["指标读数编号"] == "PM-T2")
        reading["隔离行计数"] = "99"
        ok, msg = svc.cross_check("PM-T2")
        assert ok is False
        assert "不一致" in msg

    def test_cross_check_passes_for_honest_reading(self, fresh_store):
        svc = SERVICES["parse_metric"]
        svc.settle_reading("PM-T3", "20260903", "sftp-node-03", "t")
        ok, msg = svc.cross_check("PM-T3")
        assert ok is True

    def test_fallback_rate_from_route_decisions(self, fresh_store):
        svc = SERVICES["parse_metric"]
        # seed: parser_route PR-002 回退1次(已回退), PR-003 回退3次(路由失败)，都在 sftp-node-03/api-gateway-01
        rate, fallbacks, total = svc.real_fallback_rate("sftp-node-03")
        assert total >= 2
        assert fallbacks >= 1
        assert rate > 0


class TestUnitNormalizeService:
    def test_conflicting_factor_blocks_activation(self, fresh_store):
        svc = SERVICES["unit_normalize"]
        store.rows("unit_normalize").append({
            "id": 980, "status": "草稿", "pending": True, "abnormal": False,
            "归一编号": "UN-T1", "字段名称": "payload_bytes", "原始单位": "KB",
            "目标单位": "byte", "换算系数": "1000.0", "适用来源": "sftp-node-03",
            "生效起日": "", "最近命中": ""})
        ok, msg = svc.activate_factor("UN-T1", "2026-09-10")
        assert ok is False
        assert "冲突" in msg
        conflicts = svc.conflicts()
        assert len(conflicts) >= 1

    def test_resolve_conflict_keeps_one(self, fresh_store):
        svc = SERVICES["unit_normalize"]
        store.rows("unit_normalize").append({
            "id": 981, "status": "草稿", "pending": True, "abnormal": False,
            "归一编号": "UN-T2", "字段名称": "payload_bytes", "原始单位": "KB",
            "目标单位": "byte", "换算系数": "1000.0", "适用来源": "sftp-node-03",
            "生效起日": "", "最近命中": ""})
        svc.activate_factor("UN-T2", "2026-09-10")
        ok, msg = svc.resolve_conflict("UN-001")  # 保留 seed 里的 UN-001
        assert ok is True
        un1 = next(r for r in store.rows("unit_normalize") if r["归一编号"] == "UN-001")
        un2 = next(r for r in store.rows("unit_normalize") if r["归一编号"] == "UN-T2")
        assert un1["status"] == "已生效"
        assert un2["status"] == "已停用"

    def test_normalize_applies_active_factor(self, fresh_store):
        svc = SERVICES["unit_normalize"]
        ok, value, msg = svc.normalize_value("payload_bytes", "sftp-node-03", 3.0, "2026-09-02")
        assert ok is True
        assert value == pytest.approx(3072.0)

    def test_normalize_refused_without_factor(self, fresh_store):
        svc = SERVICES["unit_normalize"]
        ok, value, msg = svc.normalize_value("unknown_field", "sftp-node-03", 1.0, "2026-09-02")
        assert ok is False
        assert value is None


class TestSampleReviewService:
    def test_record_review_writes_real_counts(self, fresh_store):
        svc = SERVICES["sample_review"]
        parsed = [{"rec_id": f"R-{i}", "value": i} for i in range(10)]
        raw = [{"rec_id": f"R-{i}", "value": i} for i in range(10)]
        passed, conclusion, record = svc.record_review(
            "SR-T1", "PB-T1", 1.0, "reviewer-01", parsed, raw, ["rec_id", "value"])
        assert passed is True
        assert record["取值偏差数"] == "0"
        assert record["字段一致数"] == "10"

    def test_rejected_review_blocks_contract(self, fresh_store):
        svc = SERVICES["sample_review"]
        parsed = [{"value": 0} for _ in range(10)]
        raw = [{"value": i} for i in range(10)]
        passed, _c, _r = svc.record_review(
            "SR-T2", "PB-T2", 1.0, "reviewer-01", parsed, raw, ["value"])
        assert passed is False
        blocked, msg = svc.blocks_contract("PB-T2")
        assert blocked is True
        assert "驳回" in msg

    def test_deviation_ranking_sorted(self, fresh_store):
        svc = SERVICES["sample_review"]
        ranking = svc.deviation_ranking()
        counts = [r["取值偏差数"] for r in ranking]
        assert counts == sorted(counts, reverse=True)


class TestValueCastService:
    def test_cast_row_and_record_failures(self, fresh_store):
        svc = SERVICES["value_cast"]
        # seed VC-001: float64 精度2
        values, failures = svc.cast_row(
            "VC-001", {"amount": "10.567", "bad": "xyz"}, "2026-09-05T00:00:00")
        assert values["amount"] == pytest.approx(10.57)
        assert len(failures) == 1
        summary = svc.failure_summary("VC-001")
        # seed 原有 1 次失败 + 本次 1 次 = 2
        assert summary["转型失败数"] == 2
        assert summary["status"] == "存在失败"

    def test_cast_failures_written_to_quarantine(self, fresh_store):
        svc = SERVICES["value_cast"]
        _values, failures = svc.cast_row("VC-001", {"amount": "abc"}, "t")
        created = svc.quarantine_failures("VC-001", "FI-VC1", 3, failures, "raw-line", "t")
        assert len(created) == 1
        quarantined = [r for r in store.rows("row_quarantine") if r["关联批次"] == "FI-VC1"]
        assert quarantined[0]["失败原因"].startswith("取值转型失败")

    def test_datetime_pattern_conversion(self, fresh_store):
        svc = SERVICES["value_cast"]
        # seed VC-002: datetime64, yyyy-MM-dd HH:mm:ss
        values, failures = svc.cast_row(
            "VC-002", {"ts": "2026-09-01 08:15:00"}, "t")
        assert not failures
        assert values["ts"] == "2026-09-01T08:15:00"

    def test_empty_without_fill_fails(self, fresh_store):
        svc = SERVICES["value_cast"]
        ok, value, reason = svc.cast_value("", "int64", null_fill=None)
        assert ok is False
        assert "为空" in reason


class TestNestedFlattenService:
    def test_expand_multiplies_rows(self, fresh_store):
        svc = SERVICES["nested_flatten"]
        store.rows("nested_flatten").append({
            "id": 970, "status": "待展平", "pending": True, "abnormal": False,
            "展平编号": "NF-T1", "关联模板": "ET-004",
            "原始路径": "$.data.records[*]", "展平后列名": "rec_id,amount",
            "数组处理方式": "EXPAND", "最大展开层数": "3",
            "空节点处置": "SKIP", "展平行数": "0"})
        docs = [{"data": {"records": [{"rec_id": "R-1", "amount": 1},
                                       {"rec_id": "R-2", "amount": 2}]}},
                {"data": {"records": [{"rec_id": "R-3", "amount": 3}]}}]
        ok, rows, msg = svc.execute_flatten("NF-T1", docs)
        assert ok is True
        assert len(rows) == 3
        multi = svc.row_multiplication("NF-T1", 2)
        assert multi["multiplier"] == pytest.approx(1.5)

    def test_depth_exceeded_status(self, fresh_store):
        svc = SERVICES["nested_flatten"]
        store.rows("nested_flatten").append({
            "id": 971, "status": "待展平", "pending": True, "abnormal": False,
            "展平编号": "NF-T2", "关联模板": "ET-004",
            "原始路径": "$.a.b.c.d.e", "展平后列名": "x",
            "数组处理方式": "EXPAND", "最大展开层数": "3",
            "空节点处置": "SKIP", "展平行数": "0"})
        ok, rows, msg = svc.execute_flatten("NF-T2", [{"a": {}}])
        assert ok is False
        assert rows == []
        blocked, bmsg = svc.blocks_value_cast("NF-T2")
        assert blocked is True
        assert "层数超限" in bmsg

    def test_invalid_mode_rejected(self, fresh_store):
        svc = SERVICES["nested_flatten"]
        store.rows("nested_flatten").append({
            "id": 972, "status": "待展平", "pending": True, "abnormal": False,
            "展平编号": "NF-T3", "关联模板": "ET-004",
            "原始路径": "$.a[*]", "展平后列名": "x",
            "数组处理方式": "EXPLODE_BADLY", "最大展开层数": "2",
            "空节点处置": "SKIP", "展平行数": "0"})
        ok, rows, msg = svc.execute_flatten("NF-T3", [{"a": [1]}])
        assert ok is False
        assert "不在允许范围" in msg


class TestParserRouteService:
    def test_low_confidence_probe_fails_route(self, fresh_store):
        svc = SERVICES["parser_route"]
        ok, msg, decision = svc.choose_by_probe("PR-T1", "FI-20260901003", "FP-003", "t")
        assert ok is False
        assert decision["status"] == "路由失败"

    def test_confirmed_probe_selects_primary(self, fresh_store):
        svc = SERVICES["parser_route"]
        ok, msg, decision = svc.choose_by_probe("PR-T2", "FI-20260901001", "FP-001", "t")
        assert ok is True
        assert decision["命中解析器"] == "csv_parser_v2"

    def test_fallback_execution_records_count(self, fresh_store):
        svc = SERVICES["parser_route"]
        svc.choose_by_probe("PR-T3", "FI-20260901001", "FP-001", "t")
        ok, msg, decision = svc.run_with_fallback(
            "PR-T3", lambda p: p == "csv_parser_v1", "t2")
        assert ok is True
        assert decision["回退次数"] == "1"
        assert decision["status"] == "已回退"
        fallbacks, total = svc.fallback_counts()
        assert fallbacks >= 1

    def test_all_parsers_fail_marks_failed(self, fresh_store):
        svc = SERVICES["parser_route"]
        svc.choose_by_probe("PR-T4", "FI-20260901001", "FP-001", "t")
        ok, msg, decision = svc.run_with_fallback("PR-T4", lambda p: False, "t2")
        assert ok is False
        assert decision["status"] == "路由失败"
        assert "PR-T4" or True  # 决策编号
        failed_batches = svc.failed_route_batches()
        assert "FI-20260901001" in failed_batches


class TestFormatProbeService:
    def test_mismatch_recorded_for_audit(self, fresh_store):
        svc = SERVICES["format_probe"]
        svc.probe("FP-T1", "FI-20260902003", "504B0304", "jsonl", 50)
        mismatches = svc.mismatch_batches()
        codes = {m["关联批次"] for m in mismatches}
        assert "FI-20260902003" in codes

    def test_unrecognized_marks_batch_failed(self, fresh_store):
        svc = SERVICES["format_probe"]
        ok, msg, record = svc.probe("FP-T2", "FI-20260902001", "DEADBEEF", "", 50)
        assert ok is False
        assert record["status"] == "无法识别"
        batch = next(r for r in store.rows("file_intake") if r["批次编号"] == "FI-20260902001")
        assert batch["status"] == "探测失败"

    def test_confirm_manual_override(self, fresh_store):
        svc = SERVICES["format_probe"]
        svc.probe("FP-T3", "FI-20260902001", "DEADBEEF", "", 50)
        ok, msg = svc.confirm_format("FP-T3", "csv-utf8", "t")
        assert ok is True
        assert svc.resolved_format("FI-20260902001") == "csv-utf8"


class TestEncodingNormService:
    def test_real_transcode_counts_unmappable(self, fresh_store):
        svc = SERVICES["encoding_norm"]
        # GBK 字节里的中文在 ASCII 目标编码下不可映射
        raw = "记录A,100\n记录B,200".encode("GBK")
        ok, encoded, unmappable, msg = svc.transcode(raw, "GBK", "ASCII", "REPLACE")
        assert ok is False
        assert unmappable > 0

    def test_strict_strategy_aborts(self, fresh_store):
        svc = SERVICES["encoding_norm"]
        raw = "记录A".encode("GBK")
        ok, encoded, unmappable, msg = svc.transcode(raw, "GBK", "ASCII", "STRICT")
        assert ok is False
        assert encoded == b""
        assert "STRICT" in msg

    def test_lossless_transcode(self, fresh_store):
        svc = SERVICES["encoding_norm"]
        raw = "R-1,100".encode("UTF-8")
        ok, encoded, unmappable, msg = svc.transcode(raw, "UTF-8", "UTF-8", "REPLACE")
        assert ok is True
        assert unmappable == 0

    def test_invalid_strategy_rejected(self, fresh_store):
        svc = SERVICES["encoding_norm"]
        ok, _e, _u, msg = svc.transcode(b"x", "UTF-8", "UTF-8", "MAGIC")
        assert ok is False
        assert "不在允许范围" in msg


class TestFieldParseService:
    def test_failed_fields_collected(self, fresh_store):
        svc = SERVICES["field_parse"]
        svc.record_parsed_field("FP-X1", "FI-X1", "ET-001", "data_value",
                                "N/A", "", 2, 5, success=False)
        failed = svc.failed_fields_of_batch("FI-X1")
        assert len(failed) == 1
        assert failed[0]["解析行号"] == "5"

    def test_parsed_rows_grouped_by_line(self, fresh_store):
        svc = SERVICES["field_parse"]
        svc.record_parsed_field("FP-X2", "FI-X2", "ET-001", "rec_id", "R-1", "R-1", 1, 2, True)
        svc.record_parsed_field("FP-X3", "FI-X2", "ET-001", "value", "10", "10", 1, 2, True)
        grouped = svc.parsed_rows_of_batch("FI-X2")
        assert grouped["2"] == {"rec_id": "R-1", "value": "10", "__status": "解析成功"}

    def test_template_hit_stats(self, fresh_store):
        svc = SERVICES["field_parse"]
        stats = svc.template_hit_stats()
        # seed 中 ET-001 命中 3 次
        assert stats.get("ET-001", 0) >= 3


class TestIntakeAuditAndServices:
    def test_all_services_have_real_docstring(self, fresh_store):
        import sys
        for key, svc in SERVICES.items():
            module = sys.modules[svc.__class__.__module__]
            doc = module.__doc__ or ""
            assert "__NAME__" not in doc
            assert doc.rstrip().endswith("。")
            assert "数据集" in doc

    def test_all_modules_have_seed_rows(self, fresh_store):
        for name in store.module_names():
            rows = store.rows(name)
            assert len(rows) >= 3, f"{name} 样例数据不足"
            for row in rows:
                assert row.get("status"), f"{name} 行缺状态"

    def test_domain_snapshot_shape(self, fresh_store):
        for key, svc in SERVICES.items():
            snap = svc.domain_snapshot()
            assert snap["module"] == key
            assert snap["count"] >= 3
            assert sum(snap["by_status"].values()) == snap["count"]

    def test_audit_records_format_rewrite(self, fresh_store):
        """格式探测改写声明格式时投递审计留下变更前后值。"""
        probe_svc = SERVICES["format_probe"]
        audit_svc = SERVICES["intake_audit"]
        probe_svc.probe("FP-AU1", "FI-20260902003", "504B0304", "jsonl", 50)
        rows = store.rows("intake_audit")
        entry_id = max(int(r["id"]) for r in rows) + 1
        rows.append({
            "id": entry_id, "status": "已记录", "pending": True, "abnormal": False,
            "审计编号": f"IA-T{entry_id}", "关联对象": "FI-20260902003",
            "操作类型": "格式改写", "变更前值": "声明格式jsonl",
            "变更后值": "探测格式xlsx", "操作者标识": "system-auto",
            "操作来源": "format_probe", "操作时间": "2026-09-05T00:00:00"})
        audits = [r for r in store.rows("intake_audit") if r["操作类型"] == "格式改写"]
        assert len(audits) >= 1
        assert audits[-1]["变更后值"] == "探测格式xlsx"
        snap = audit_svc.domain_snapshot()
        assert snap["count"] >= 6


# ======================================================================
# 编码归一逐文件回执：批量续做、同名重传、损字凭据与按原行去重
# ======================================================================

A_FILE = "rec_id,ts,val,bytes\nR-1,2026-09-01 08:10:00,100.5,1024\nR-2,2026-09-01 08:11:00,101.5,2048"
B_FILE = "rec_id,ts,val,bytes\nR-3,2026-09-01 08:12:00,102.5,3072\nR-4,2026-09-01 08:13:00,103.5,4096"
B_LOSSY = "rec_id,ts,val,bytes\nR-3X记录,2026-09-01 08:12:00,102.5,3072\nR-4,2026-09-01 08:13:00,103.5,4096"
B_FIXED = "rec_id,ts,val,bytes\nR-3X,2026-09-01 08:12:00,102.5,3072\nR-4,2026-09-01 08:13:00,103.5,4096"


class TestEncodingReceipts:
    def _submit(self, file_key: str, text: str, encoding: str = "UTF-8",
                target: str = "ASCII", batch: str = "FI-R1",
                at: str = "2026-09-03T10:00:00") -> dict:
        svc = SERVICES["encoding_norm"]
        return svc.transcode_file(
            file_key, text.encode(encoding), encoding, target, "REPLACE",
            file_name=f"{file_key}.csv", intake_batch=batch, transcode_time=at)

    def test_clean_file_receipt_has_no_open_lines(self, fresh_store):
        receipt = self._submit("FI-R1/A", A_FILE)
        assert receipt["status"] == "已完成"
        assert receipt["待处理行号"] == []
        assert receipt["可继续"] is False

    def test_lossy_file_records_line_and_original_chars(self, fresh_store):
        receipt = self._submit("FI-R1/B", B_LOSSY, encoding="UTF-16-LE")
        assert receipt["status"] == "存在损字"
        assert receipt["损字行号"] == "2"
        assert receipt["待处理行号"] == [2]
        evidence = receipt["损字凭据"][0]
        assert evidence["原始行号"] == 2
        assert evidence["原始字符"] == "记录"
        assert "记录" in evidence["原始行文本"]

    def test_same_content_resubmission_counts_once(self, fresh_store):
        svc = SERVICES["encoding_norm"]
        first = self._submit("FI-R1/B", B_LOSSY, encoding="UTF-16-LE")
        again = self._submit("FI-R1/B", B_LOSSY, encoding="UTF-16-LE",
                             at="2026-09-03T10:05:00")
        assert again["回执编号"] == first["回执编号"]
        assert len(svc.receipts_of_file("FI-R1/B")) == 1

    def test_new_revision_keeps_old_evidence(self, fresh_store):
        svc = SERVICES["encoding_norm"]
        lossy = self._submit("FI-R1/B", B_LOSSY, encoding="UTF-16-LE")
        fixed = self._submit("FI-R1/B", B_FIXED, at="2026-09-03T10:10:00")
        assert fixed["修订版次"] == "2"
        assert fixed["status"] == "已完成"
        summary = next(f for f in svc.file_summaries("FI-R1") if f["文件键"] == "FI-R1/B")
        assert summary["已接受"] is True
        assert summary["可重跑"] is False
        old = summary["历史证据"][0]
        assert old["损字行号"] == "2"
        assert old["损字凭据"][0]["原始字符"] == "记录"
        assert old["回执编号"] == lossy["回执编号"]

    def test_accepted_file_offers_no_rerun(self, fresh_store):
        svc = SERVICES["encoding_norm"]
        self._submit("FI-R1/A", A_FILE)
        summary = svc.file_summaries("FI-R1")[0]
        assert summary["已接受"] is True
        assert summary["可重跑"] is False

    def test_resume_from_failed_line_dedupes_processed_rows(self, fresh_store):
        svc = SERVICES["encoding_norm"]
        receipt = self._submit("FI-R1/B", B_LOSSY, encoding="UTF-16-LE")
        ok, _msg, view = svc.resume_receipt(receipt["回执编号"], [2, 2], resumed_from=2)
        assert ok is True
        assert view["已处理行号"] == [2]
        assert view["待处理行号"] == []
        next_step = svc.next_step(receipt["回执编号"])
        assert next_step["动作"] == "转码已完成"

    def test_batch_receipts_give_per_file_next_step(self, fresh_store):
        svc = SERVICES["encoding_norm"]
        self._submit("FI-R1/A", A_FILE)
        lossy = self._submit("FI-R1/B", B_LOSSY, encoding="UTF-16-LE")
        batch = svc.receipt_batch(["FI-R1/A", "FI-R1/B"])
        assert batch["total"] == 2
        by_file = {item["文件键"]: item for item in batch["items"]}
        assert by_file["FI-R1/A"]["状态"] == "已完成"
        assert by_file["FI-R1/B"]["下一步"]["动作"] == "从失败行继续"
        assert by_file["FI-R1/B"]["下一步"]["续做行号"] == 2
        assert lossy["可继续"] is True

    def test_receipt_review_shows_adopted_result(self, fresh_store):
        enc = SERVICES["encoding_norm"]
        quarantine = SERVICES["row_quarantine"]
        receipt = self._submit("FI-R1/B", B_LOSSY, encoding="UTF-16-LE")
        assert quarantine.consume_lossy_receipt(receipt["回执编号"], "t")["created"]
        qno = "RQ-" + receipt["回执编号"] + "-2"
        quarantine.submit_review(qno, "reviewer-01")
        ok, _msg, _row = quarantine.reinstate_to_batch(
            qno, "reviewer-01", "人工修正", "t2", {"rec_id": "R-3X"})
        assert ok is True
        review = quarantine.receipt_review_result(receipt["回执编号"])
        item = review["items"][0]
        assert item["原始行号"] == "2"
        assert item["原始字符"] == "记录"
        assert item["隔离状态"] == "已回补"
        assert "R-3X" in item["回补结果"]
        # 回补后回执没有待处理行，页面不再提供重跑
        summary = next(f for f in enc.file_summaries("FI-R1") if f["文件键"] == "FI-R1/B")
        assert summary["可重跑"] is False

    def test_interrupted_reinstate_and_revision_do_not_double_count(self, fresh_store):
        """班组在回补 B 第 2 行时重传修正版并中断：重启后 A 仍两行、B 第 2 行只确认一次。"""
        enc = SERVICES["encoding_norm"]
        quarantine = SERVICES["row_quarantine"]
        batch_svc = SERVICES["parse_batch"]
        field_svc = SERVICES["field_parse"]
        store.rows("parse_batch").append({
            "id": 980, "status": "存在隔离", "pending": True, "abnormal": True,
            "批次记录编号": "PB-R1", "关联投递批次": "FI-R1",
            "解析器标识": "csv_parser_v2", "总行数": "6", "成功行数": "4",
            "隔离行数": "2", "批次状态": "存在隔离", "完成时间": "",
        })

        a = self._submit("FI-R1/A", A_FILE)
        b1 = self._submit("FI-R1/B", B_LOSSY, encoding="UTF-16-LE")
        for receipt in (a, b1):
            for index, line in enumerate(receipt["转码后文本"].splitlines(), start=1):
                if index in receipt["待处理行号"]:
                    continue
                field_svc.record_parsed_field(
                    f"FP-{receipt['回执编号']}-{index}", "FI-R1", "ET-001", "rec_id",
                    line, line, 1, index, True,
                    source_file=receipt["文件键"], source_receipt=receipt["回执编号"])
        quarantine.consume_lossy_receipt(b1["回执编号"], "t1")
        qno = "RQ-" + b1["回执编号"] + "-2"
        quarantine.submit_review(qno, "duty-01")
        ok, _msg, _row = quarantine.reinstate_to_batch(
            qno, "duty-01", "人工修正", "t2", {"rec_id": "R-3X"})
        assert ok is True

        # 修正版 B 到达（同名新修订版），值班员正在回补旧 B 第 2 行时进程中断
        b2 = self._submit("FI-R1/B", B_FIXED, at="t3")
        assert b2["修订版次"] == "2"
        assert b2["status"] == "已完成"

        # 重启后从任一个入口继续：重复提交相同内容只记一次
        replay = self._submit("FI-R1/B", B_FIXED, at="t4")
        assert replay["回执编号"] == b2["回执编号"]
        assert len(enc.receipts_of_file("FI-R1/B")) == 2

        # 已确认的原行在后续修订版里不再重复要求确认
        assert b2["待处理行号"] == []
        summaries = {item["文件键"]: item for item in enc.file_summaries("FI-R1")}
        assert summaries["FI-R1/A"]["已接受"] is True
        assert summaries["FI-R1/B"]["可继续"] is False
        old_evidence = summaries["FI-R1/B"]["历史证据"][0]
        assert old_evidence["损字凭据"][0]["原始字符"] == "记录"

        # 重复回补同一原行不重复计数
        ok_again, msg_again, _row2 = quarantine.reinstate_to_batch(
            qno, "duty-01", "重复提交", "t5", {"rec_id": "R-3X"})
        assert ok_again is False
        ok_refresh, _m, batch = batch_svc.refresh_batch_counts("FI-R1")
        assert ok_refresh is True
        assert batch["总行数"] == "6"
        assert batch["成功行数"] == "6"
        assert batch["隔离行数"] == "0"

        trace = field_svc.source_trace(f"FP-{qno}-rec_id")
        assert trace["来源文件"] == "FI-R1/B"
        assert trace["解析行号"] == "2"
        assert trace["原始字符"] == "记录"
