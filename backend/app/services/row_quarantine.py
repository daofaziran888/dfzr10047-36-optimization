"""坏行隔离领域服务：归集解析失败行及其失败原因，支持复核回补流程，产出隔离行数据集。"""
from __future__ import annotations

import json
from typing import Any

from app.services.base import BaseModuleService
from app.store import store


class RowQuarantineService(BaseModuleService):
    MODULE = "row_quarantine"
    ENTITY = "隔离行"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["隔离编号", "关联批次", "原始行号", "失败字段", "失败原因", "原始行文本", "复核结论", "隔离时间"]
    REQUIRED_FIELDS = ["隔离编号", "关联批次", "原始行号"]
    STATUS_ORDER = ["已隔离", "复核中", "已回补", "已废弃"]
    ACTION_RULES = {"提交复核": "复核中", "回补批次": "已回补", "废弃隔离行": "已废弃"}
    NEGATIVE_ACTIONS = ["废弃隔离行"]

    # 只有这些失败原因允许人工回补，其余必须走废弃
    REINSTATABLE_REASONS = ("日期格式", "格式异常", "人工确认", "可修正")

    # 编码损字行只有在复核生效（状态=复核中）后才允许按原行回补
    ENCODING_FIELD = "encoding"
    REVIEWED_STATUS = "复核中"

    # 已确认回补的原行账本：同一批次同一原行只计一次，跨回执/跨修订版去重
    REINSTATE_LEDGER = "_quarantine_reinstates"

    def quarantine_failure(self, intake_batch: str, row_num: int, raw_text: str,
                           failed_field: str, reason: str,
                           quarantine_time: str, *, file_key: str = "",
                           receipt_no: str = "",
                           lossy_line: dict[str, Any] | None = None
                           ) -> tuple[bool, str, dict[str, Any] | None]:
        """登记隔离行：同一来源文件同一行号重复登记时拒绝，避免隔离计数虚高。

        带回执时按「回执 + 原行号」去重，同名文件不同修订版各自保留损字凭据；
        只带文件键时按「文件 + 原行号」去重；都不带时保留按批次行号去重的老口径。
        """
        rows = store.rows(self.MODULE)
        if receipt_no:
            exists = any(
                r.get("回执编号") == receipt_no
                and str(r.get("原始行号")) == str(row_num)
                for r in rows
            )
        elif file_key:
            exists = any(
                r.get("文件键") == file_key
                and str(r.get("原始行号")) == str(row_num)
                for r in rows
            )
        else:
            exists = any(
                r.get("关联批次") == intake_batch
                and str(r.get("原始行号")) == str(row_num)
                for r in rows
            )
        if exists:
            return False, (
                f"批次 {intake_batch} 行 {row_num} 已在隔离清单中，不得重复登记"
            ), None

        entry_id = max((int(r.get("id", 0)) for r in rows), default=0) + 1
        identifier = receipt_no or file_key or intake_batch
        identifier = "".join(
            char if char.isalnum() or char in "-_." else "-" for char in str(identifier)
        ).strip("-") or "row"
        entry = {
            "id": entry_id,
            "status": "已隔离",
            "pending": True,
            "abnormal": False,
            "隔离编号": f"RQ-{identifier}-{row_num}",
            "关联批次": intake_batch,
            "原始行号": str(row_num),
            "失败字段": failed_field,
            "失败原因": reason,
            "原始行文本": raw_text,
            "复核结论": "",
            "隔离时间": quarantine_time,
        }
        if file_key:
            entry["文件键"] = file_key
        if receipt_no:
            entry["回执编号"] = receipt_no
        if lossy_line:
            entry["原始字符"] = lossy_line.get("原始字符", "")
            entry["转码后行文本"] = lossy_line.get("转码后行文本", "")
        rows.append(entry)
        return True, f"批次 {intake_batch} 行 {row_num} 已隔离（{failed_field}: {reason}）", dict(entry)

    def consume_lossy_receipt(self, receipt_no: str,
                              quarantine_time: str) -> dict[str, Any]:
        """坏行隔离消费损字隔离清单：按回执里的损字凭据逐行建隔离行。

        重复消费同一回执只补建缺失行，已登记的损字行不会翻倍。
        """
        from app.services.encoding_norm import EncodingNormService

        receipt = EncodingNormService().receipt_of(receipt_no)
        if receipt.get("status") == "未找到":
            return {"回执编号": receipt_no, "created": [], "skipped": 0,
                    "message": receipt.get("message", "回执不存在")}

        created: list[str] = []
        skipped = 0
        for line in receipt.get("损字凭据") or []:
            ok, _msg, row = self.quarantine_failure(
                str(receipt.get("关联批次") or ""), int(line["原始行号"]),
                str(line.get("原始行文本") or ""), self.ENCODING_FIELD,
                str(line.get("失败原因") or "编码归一损字"), quarantine_time,
                file_key=str(receipt.get("文件键") or ""),
                receipt_no=receipt_no, lossy_line=line)
            if ok and row is not None:
                created.append(str(row["隔离编号"]))
            else:
                skipped += 1
        return {"回执编号": receipt_no, "created": created, "skipped": skipped,
                "message": f"回执 {receipt_no} 损字行已消费：新增 {len(created)}，已存在 {skipped}"}

    def receipt_review_result(self, receipt_no: str) -> dict[str, Any]:
        """从回执打开每个原行此次真正采用的转码结果或回补结果。"""
        from app.services.encoding_norm import EncodingNormService

        receipt = EncodingNormService().receipt_of(receipt_no)
        rows = [
            r for r in store.rows(self.MODULE)
            if r.get("回执编号") == receipt_no
        ]
        by_line = {str(r.get("原始行号")): r for r in rows}
        items: list[dict[str, Any]] = []
        for line in receipt.get("损字凭据") or []:
            key = str(line["原始行号"])
            row = by_line.get(key, {})
            adopted = row.get("复核结论") or ""
            items.append({
                "原始行号": key,
                "原始字符": line.get("原始字符", ""),
                "采用的转码结果": line.get("转码后行文本", ""),
                "隔离状态": row.get("status", "未隔离"),
                "回补结果": row.get("修正取值", "") if row.get("status") == "已回补" else "",
                "复核结论": adopted,
            })
        return {"回执编号": receipt_no, "items": items}

    def submit_review(self, quarantine_no: str, reviewer: str) -> tuple[bool, str]:
        """提交复核：已回补/已废弃的隔离行不能再回到复核中。"""
        for row in store.rows(self.MODULE):
            if row.get("隔离编号") != quarantine_no:
                continue
            if row.get("status") in ("已回补", "已废弃"):
                return False, (
                    f"隔离行 {quarantine_no} 已终态（{row.get('status')}），不能回到复核中"
                )
            row["status"] = "复核中"
            row["pending"] = True
            row["复核人"] = reviewer
            return True, f"隔离行 {quarantine_no} 已进入复核，复核人 {reviewer}"
        return False, f"隔离行 {quarantine_no} 不存在"

    def reinstate_to_batch(self, quarantine_no: str, reviewer: str,
                           conclusion: str, review_time: str,
                           corrected: dict[str, Any] | None = None
                           ) -> tuple[bool, str, dict[str, Any] | None]:
        """回补批次：校验失败原因是否可人工修正，回补后同步批次成功/隔离行数。

        - 编码损字行必须复核生效（状态=复核中）后才能按原行回补；
        - 同一来源文件的同一原行只算一次，重复提交/中断重放不重复计数；
        - 修正取值随回补写回解析批次，供字段解析直接读取。
        """
        target = None
        for row in store.rows(self.MODULE):
            if row.get("隔离编号") == quarantine_no:
                target = row
                break
        if target is None:
            return False, f"隔离行 {quarantine_no} 不存在", None
        if target.get("status") == "已废弃":
            return False, f"隔离行 {quarantine_no} 已废弃，不能回补", None
        if target.get("status") == "已回补":
            return False, f"隔离行 {quarantine_no} 已回补，不能重复回补", None

        file_key = str(target.get("文件键") or target.get("关联批次") or "")
        row_num = str(target.get("原始行号") or "")
        ledger = store.rows(self.REINSTATE_LEDGER)
        # 原行身份 = 来源文件 + 原行号：同名文件重传、换修订版重放都只计一次
        prior = next(
            (r for r in ledger
             if r.get("文件键") == file_key and r.get("原始行号") == row_num),
            None)
        if prior is not None:
            return True, (
                f"隔离行 {quarantine_no} 的原行（{file_key} 行 {row_num}）此前已确认回补，"
                f"按原行去重只计一次"
            ), dict(target)

        reason = str(target.get("失败原因") or "")
        if target.get("失败字段") == self.ENCODING_FIELD:
            if target.get("status") != self.REVIEWED_STATUS:
                return False, (
                    f"隔离行 {quarantine_no} 为损字行，需先复核生效再按原行回补"
                ), dict(target)
        elif not any(k in reason for k in self.REINSTATABLE_REASONS):
            return False, (
                f"隔离行 {quarantine_no} 失败原因「{reason}」不属于可人工修正范围，"
                f"只能废弃不能回补"
            ), dict(target)

        target["status"] = "已回补"
        target["pending"] = False
        target["abnormal"] = False
        target["复核结论"] = f"{reviewer}: {conclusion}"
        target["复核时间"] = review_time
        if corrected:
            target["修正取值"] = json.dumps(corrected, ensure_ascii=False, sort_keys=True)

        ledger.append({
            "id": max((int(r.get("id", 0)) for r in ledger), default=0) + 1,
            "文件键": file_key,
            "原始行号": row_num,
            "隔离编号": quarantine_no,
            "回执编号": target.get("回执编号", ""),
            "复核结论": target["复核结论"],
            "回补时间": review_time,
        })

        batch_no = target.get("关联批次")
        for batch in store.rows("parse_batch"):
            if batch.get("关联投递批次") == batch_no:
                success = str(batch.get("成功行数") or "0")
                quarantined = str(batch.get("隔离行数") or "0")
                batch["成功行数"] = str(int(success) + 1 if success.isdigit() else 1)
                batch["隔离行数"] = str(
                    max(0, int(quarantined) - 1) if quarantined.isdigit() else 0)
                if batch.get("隔离行数") == "0":
                    batch["批次状态"] = "已闭合"
                    batch["status"] = "已闭合"
                    batch["pending"] = False
                    batch["abnormal"] = False
                break

        if corrected:
            self._write_back_to_parse(batch_no, target, corrected)

        return True, (
            f"隔离行 {quarantine_no} 已回补进批次 {batch_no}，"
            f"批次成功行数 +1、隔离行数 -1"
        ), dict(target)

    def _write_back_to_parse(self, intake_batch: str, source: dict[str, Any],
                             corrected: dict[str, Any]) -> None:
        """把复核生效的修正行写回字段解析批次，并与来源文件、原行号关联。"""
        rows = store.rows("field_parse")
        row_num = str(source.get("原始行号") or "")
        for field_name, value in corrected.items():
            entry_id = max((int(r.get("id", 0)) for r in rows), default=0) + 1
            rows.append({
                "id": entry_id,
                "status": "解析成功",
                "pending": False,
                "abnormal": False,
                "解析编号": f"FP-{source.get('隔离编号')}-{field_name}",
                "关联批次": intake_batch,
                "命中模板": source.get("命中模板", ""),
                "字段名称": str(field_name),
                "原始取值": source.get("原始行文本", ""),
                "解析取值": str(value),
                "解析耗时": "0",
                "解析行号": row_num,
                "来源文件": source.get("文件键", ""),
                "来源回执": source.get("回执编号", ""),
                "回补来源": source.get("隔离编号", ""),
            })

    def discard_row(self, quarantine_no: str, reviewer: str, reason: str) -> tuple[bool, str]:
        """废弃隔离行：终态，不可再回补。"""
        for row in store.rows(self.MODULE):
            if row.get("隔离编号") != quarantine_no:
                continue
            if row.get("status") == "已废弃":
                return False, f"隔离行 {quarantine_no} 已废弃"
            row["status"] = "已废弃"
            row["pending"] = False
            row["abnormal"] = True
            row["复核结论"] = f"{reviewer}: 废弃，{reason}"
            return True, f"隔离行 {quarantine_no} 已废弃：{reason}"
        return False, f"隔离行 {quarantine_no} 不存在"

    def quarantine_stats(self, intake_batch: str) -> dict[str, int]:
        """按批次输出隔离真实计数，供解析指标结算隔离率。"""
        rows = [r for r in store.rows(self.MODULE) if r.get("关联批次") == intake_batch]
        return {
            "total": len(rows),
            "isolated": sum(1 for r in rows if r.get("status") == "已隔离"),
            "reviewing": sum(1 for r in rows if r.get("status") == "复核中"),
            "reinstated": sum(1 for r in rows if r.get("status") == "已回补"),
            "discarded": sum(1 for r in rows if r.get("status") == "已废弃"),
        }

    def unreviewed_rows(self, intake_batch: str) -> list[dict[str, Any]]:
        """未复核隔离行清单，输出契约据此阻断批次通过。"""
        return [
            {"隔离编号": r.get("隔离编号"), "原始行号": r.get("原始行号"),
             "失败字段": r.get("失败字段"), "失败原因": r.get("失败原因")}
            for r in store.rows(self.MODULE)
            if r.get("关联批次") == intake_batch
            and r.get("status") in ("已隔离", "复核中")
        ]

    def blocks_contract(self, intake_batch: str) -> tuple[bool, str]:
        """存在未复核隔离行时批次不得进入输出契约。"""
        pending = self.unreviewed_rows(intake_batch)
        if pending:
            return True, (
                f"批次 {intake_batch} 有 {len(pending)} 行隔离未复核"
                f"（行号 {[p['原始行号'] for p in pending][:5]}），输出契约不得通过"
            )
        return False, f"批次 {intake_batch} 无未复核隔离行"
