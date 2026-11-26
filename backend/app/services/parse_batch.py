"""解析批次领域服务：汇聚每次解析的行级统计与闭合判定，产出批次记录数据集。"""
from __future__ import annotations

from typing import Any

from app.services.base import BaseModuleService
from app.store import store


class ParseBatchService(BaseModuleService):
    MODULE = "parse_batch"
    ENTITY = "批次记录"
    OPERATION_TERM = "聚合"
    LIST_FIELDS = ["批次记录编号", "关联投递批次", "解析器标识", "总行数", "成功行数", "隔离行数", "批次状态", "完成时间"]
    REQUIRED_FIELDS = ["批次记录编号", "关联投递批次", "解析器标识"]
    STATUS_ORDER = ["解析中", "已闭合", "存在隔离", "已作废"]
    ACTION_RULES = {"闭合批次": "已闭合", "登记隔离": "存在隔离", "作废批次": "已作废"}
    NEGATIVE_ACTIONS = ["作废批次"]

    @staticmethod
    def _int(row: dict[str, Any], field: str) -> int:
        text = str(row.get(field) or "").strip()
        return int(text) if text.isdigit() else 0

    def _find_by_intake(self, intake_batch: str) -> dict[str, Any] | None:
        for row in store.rows(self.MODULE):
            if row.get("关联投递批次") == intake_batch:
                return row
        return None

    def tally_from_field_parse(self, intake_batch: str) -> dict[str, int]:
        """从字段解析明细聚合行级统计：按「来源文件 + 原行号」去重后计成功/失败行。"""
        parsed = store.rows("field_parse")
        rows_of_batch = [r for r in parsed if r.get("关联批次") == intake_batch]
        row_keys: dict[tuple[str, str], bool] = {}
        for r in rows_of_batch:
            line = str(r.get("解析行号") or "")
            if not line:
                continue
            key = (str(r.get("来源文件") or "batch:" + intake_batch), line)
            ok = r.get("status") == "解析成功"
            row_keys[key] = row_keys.get(key, True) and ok
        success = sum(1 for ok in row_keys.values() if ok)
        failed = sum(1 for ok in row_keys.values() if not ok)
        return {"total_rows": len(row_keys), "success_rows": success,
                "failed_rows": failed, "row_keys": row_keys}

    def tally_from_quarantine(self, intake_batch: str) -> dict[str, int]:
        """从坏行隔离明细统计真实隔离行数与已回补行数，同一原行只算一次。"""
        rows = [
            r for r in store.rows("row_quarantine")
            if r.get("关联批次") == intake_batch
        ]
        distinct: dict[tuple[str, str], dict[str, Any]] = {}
        for r in rows:
            key = (str(r.get("文件键") or "batch:" + intake_batch),
                   str(r.get("原始行号") or ""))
            # 同一原行多次登记时，以已回补/已废弃的终态为准
            if key not in distinct or r.get("status") in ("已回补", "已废弃"):
                distinct[key] = r
        values = list(distinct.values())
        return {
            "quarantined": len(values),
            "reinstated": sum(1 for r in values if r.get("status") == "已回补"),
            "discarded": sum(1 for r in values if r.get("status") == "已废弃"),
            "unreviewed": sum(1 for r in values if r.get("status") in ("已隔离", "复核中")),
        }

    def refresh_batch_counts(self, intake_batch: str) -> tuple[bool, str, dict[str, Any] | None]:
        """按字段解析与坏行隔离的真实计数刷新批次行数，不允许人工填数。

        已确认回补的原行只计一次：回补已写回字段解析的，不重复加到成功行数；
        重复提交的同一文件、同一原行也不会把总行数抬高。
        """
        batch = self._find_by_intake(intake_batch)
        if batch is None:
            return False, f"投递批次 {intake_batch} 没有对应批次记录", None
        if batch.get("status") == "已作废":
            return False, f"批次记录 {batch.get('批次记录编号')} 已作废，不再刷新计数", None

        parse_tally = self.tally_from_field_parse(intake_batch)
        quarantine_tally = self.tally_from_quarantine(intake_batch)
        parse_row_keys = parse_tally["row_keys"]
        reinstated_keys = {
            (str(r.get("文件键") or "batch:" + intake_batch),
             str(r.get("原始行号") or ""))
            for r in store.rows("row_quarantine")
            if r.get("关联批次") == intake_batch and r.get("status") == "已回补"
        }
        # 回补行已经写回字段解析的部分不再重复加成功数
        unparsed_reinstated = len(reinstated_keys - set(parse_row_keys))
        all_keys = set(parse_row_keys) | reinstated_keys
        success = parse_tally["success_rows"] + unparsed_reinstated
        quarantined = max(0, len(all_keys) - success)

        batch["总行数"] = str(len(all_keys))
        batch["成功行数"] = str(success)
        batch["隔离行数"] = str(quarantined)
        return True, (
            f"批次 {intake_batch} 计数已按真实明细刷新："
            f"总 {len(all_keys)} / 成功 {success} / 隔离 {quarantined}"
        ), dict(batch)

    def close_batch(self, intake_batch: str, close_time: str) -> tuple[bool, str, dict[str, Any] | None]:
        """闭合批次：存在未复核隔离行时不得闭合，计数必须先与明细一致。"""
        batch = self._find_by_intake(intake_batch)
        if batch is None:
            return False, f"投递批次 {intake_batch} 没有对应批次记录", None
        if batch.get("status") == "已闭合":
            return False, f"批次 {intake_batch} 已闭合，不能重复闭合", None
        if batch.get("status") == "已作废":
            return False, f"批次 {intake_batch} 已作废，不能闭合", None

        quarantine_tally = self.tally_from_quarantine(intake_batch)
        if quarantine_tally["unreviewed"] > 0:
            batch["批次状态"] = "存在隔离"
            batch["status"] = "存在隔离"
            batch["pending"] = True
            batch["abnormal"] = True
            return False, (
                f"批次 {intake_batch} 仍有 {quarantine_tally['unreviewed']} 行隔离未复核，"
                f"不得闭合"
            ), dict(batch)

        ok, _msg, _row = self.refresh_batch_counts(intake_batch)
        total = self._int(batch, "总行数")
        success = self._int(batch, "成功行数")
        if total > 0 and success == 0:
            batch["批次状态"] = "存在隔离"
            batch["status"] = "存在隔离"
            batch["pending"] = True
            batch["abnormal"] = True
            return False, f"批次 {intake_batch} 成功行数为 0，不得闭合", dict(batch)

        batch["批次状态"] = "已闭合"
        batch["status"] = "已闭合"
        batch["完成时间"] = close_time
        batch["pending"] = False
        batch["abnormal"] = False
        return True, f"批次 {intake_batch} 已闭合，成功 {success}/{total} 行", dict(batch)

    def invalidate_batch(self, intake_batch: str, reason: str) -> tuple[bool, str]:
        """作废批次：格式无法识别或路由失败时使用，作废后不得再进入契约。"""
        batch = self._find_by_intake(intake_batch)
        if batch is None:
            return False, f"投递批次 {intake_batch} 没有对应批次记录"
        if batch.get("status") == "已作废":
            return False, f"批次 {intake_batch} 已作废"
        batch["批次状态"] = "已作废"
        batch["status"] = "已作废"
        batch["pending"] = False
        batch["abnormal"] = True
        batch["作废原因"] = reason
        return True, f"批次 {intake_batch} 已作废：{reason}"

    def open_batches(self) -> list[dict[str, Any]]:
        """列出全部未闭合批次，供水位推进前置校验消费。"""
        return [
            {
                "批次记录编号": r.get("批次记录编号"),
                "关联投递批次": r.get("关联投递批次"),
                "批次状态": r.get("批次状态"),
                "隔离行数": r.get("隔离行数"),
            }
            for r in store.rows(self.MODULE)
            if r.get("批次状态") not in ("已闭合", "已作废", "闭合")
        ]

    def closed_ratio(self) -> float:
        """批次闭合率：已闭合 / 非作废总数。"""
        rows = [r for r in store.rows(self.MODULE) if r.get("批次状态") != "已作废"]
        if not rows:
            return 0.0
        closed = sum(1 for r in rows if r.get("批次状态") in ("已闭合", "闭合"))
        return closed / len(rows)
