"""字段解析领域服务：按命中模板逐字段抽取取值并记录解析质量，产出解析字段数据集。"""
from __future__ import annotations

from typing import Any

from app.services.base import BaseModuleService
from app.store import store


class FieldParseService(BaseModuleService):
    MODULE = "field_parse"
    ENTITY = "解析字段"
    OPERATION_TERM = "解析"
    LIST_FIELDS = ["解析编号", "关联批次", "命中模板", "字段名称", "原始取值", "解析取值", "解析耗时", "解析行号"]
    REQUIRED_FIELDS = ["解析编号", "关联批次", "命中模板"]
    STATUS_ORDER = ["待解析", "解析中", "解析成功", "部分失败"]
    ACTION_RULES = {"启动解析": "解析中", "确认成功": "解析成功", "登记部分失败": "部分失败"}
    NEGATIVE_ACTIONS = ["登记部分失败"]

    def record_parsed_field(self, parse_no: str, intake_batch: str, template_no: str,
                            field_name: str, raw_value: str, parsed_value: str,
                            elapsed_ms: int, row_num: int,
                            success: bool, *, source_file: str = "",
                            source_receipt: str = "") -> dict[str, Any]:
        """登记单字段解析结果，解析失败的字段连同行号可供坏行隔离消费。

        字段记录与来源文件/回执关联，后段可回查对应来源文件、原行号与原始字符。
        """
        rows = store.rows(self.MODULE)
        entry_id = max((int(r.get("id", 0)) for r in rows), default=0) + 1
        entry = {
            "id": entry_id,
            "status": "解析成功" if success else "部分失败",
            "pending": not success,
            "abnormal": not success,
            "解析编号": parse_no,
            "关联批次": intake_batch,
            "命中模板": template_no,
            "字段名称": field_name,
            "原始取值": raw_value,
            "解析取值": parsed_value,
            "解析耗时": str(elapsed_ms),
            "解析行号": str(row_num),
        }
        if source_file:
            entry["来源文件"] = source_file
        if source_receipt:
            entry["来源回执"] = source_receipt
        rows.append(entry)
        return entry

    def failed_fields_of_batch(self, intake_batch: str) -> list[dict[str, Any]]:
        """输出解析失败字段清单（含行号），坏行隔离据此建隔离行。"""
        return [
            {
                "解析编号": r.get("解析编号"),
                "字段名称": r.get("字段名称"),
                "原始取值": r.get("原始取值"),
                "解析行号": r.get("解析行号"),
            }
            for r in store.rows(self.MODULE)
            if r.get("关联批次") == intake_batch and r.get("status") == "部分失败"
        ]

    def parsed_rows_of_batch(self, intake_batch: str) -> dict[str, dict[str, Any]]:
        """按行号聚合解析成功的取值，供抽样复核与输出契约取数。"""
        grouped: dict[str, dict[str, Any]] = {}
        for r in store.rows(self.MODULE):
            if r.get("关联批次") != intake_batch:
                continue
            line = str(r.get("解析行号") or "")
            if not line:
                continue
            bucket = grouped.setdefault(line, {})
            bucket[str(r.get("字段名称"))] = r.get("解析取值")
            bucket["__status"] = (
                "部分失败" if r.get("status") == "部分失败"
                else bucket.get("__status", "解析成功")
            )
        return grouped

    def parse_batch_rows(self, batch_files: dict[str, str],
                         transcoded: dict[str, str]) -> dict[str, Any]:
        """字段解析同时读取各批转码产物：按原文件去重，同名多修订版只取最新。

        batch_files：批次 → 原文件键；transcoded：文件键 → 转码后文本。
        返回逐文件行数、去重后的来源文件清单和实际读取的行。
        """
        files: list[str] = []
        rows_by_file: dict[str, list[str]] = {}
        for _batch, file_key in batch_files.items():
            if file_key in files:
                continue
            files.append(file_key)
            rows_by_file[file_key] = [
                line for line in str(transcoded.get(file_key, "")).splitlines() if line
            ]
        return {
            "files": files,
            "rows_by_file": rows_by_file,
            "total_rows": sum(len(rows) for rows in rows_by_file.values()),
            "dedup_key": "来源文件",
        }

    def source_trace(self, parse_no: str) -> dict[str, Any]:
        """归一成功后回查对应来源文件、原行号与当时的原始字符。"""
        for r in store.rows(self.MODULE):
            if r.get("解析编号") != parse_no:
                continue
            trace = {
                "解析编号": parse_no,
                "来源文件": r.get("来源文件", ""),
                "来源回执": r.get("来源回执", ""),
                "解析行号": r.get("解析行号", ""),
                "原始取值": r.get("原始取值", ""),
            }
            for q in store.rows("row_quarantine"):
                if q.get("隔离编号") and q.get("隔离编号") == r.get("回补来源"):
                    trace["原始字符"] = q.get("原始字符", "")
                    trace["原始行文本"] = q.get("原始行文本", "")
                    break
            return trace
        return {"解析编号": parse_no, "说明": "解析字段不存在"}

    def success_rate(self, intake_batch: str) -> float:
        """批次字段级解析成功率，供解析指标交叉核对。"""
        rows = [r for r in store.rows(self.MODULE) if r.get("关联批次") == intake_batch]
        if not rows:
            return 0.0
        return sum(1 for r in rows if r.get("status") == "解析成功") / len(rows)

    def template_hit_stats(self) -> dict[str, int]:
        """按命中模板统计解析字段数，供模板版本过渡期命中分布核对。"""
        stats: dict[str, int] = {}
        for r in store.rows(self.MODULE):
            key = str(r.get("命中模板") or "")
            if key:
                stats[key] = stats.get(key, 0) + 1
        return stats
