"""编码归一领域服务：将异构来源文本统一到目标编码表，产出转码记录数据集。"""
from __future__ import annotations

import hashlib
from typing import Any

from app.services.base import BaseModuleService
from app.store import store

# 内部账本：逐文件转码回执，不进入业务模块看板，但参与断电重启后的续做核对。
LEDGER = "_encoding_receipts"


class EncodingNormService(BaseModuleService):
    MODULE = "encoding_norm"
    ENTITY = "转码记录"
    OPERATION_TERM = "标准化"
    LIST_FIELDS = ["转码编号", "关联批次", "原始编码", "目标编码", "不可映射字符数", "替换策略", "转码后字节", "转码耗时"]
    REQUIRED_FIELDS = ["转码编号", "关联批次", "原始编码"]
    STATUS_ORDER = ["待转码", "转码中", "已完成", "存在损字"]
    ACTION_RULES = {"启动转码": "转码中", "确认完成": "已完成", "登记损字": "存在损字"}
    NEGATIVE_ACTIONS = ["登记损字"]

    REPLACE = "REPLACE"
    IGNORE = "IGNORE"
    STRICT = "STRICT"
    STRATEGIES = (REPLACE, IGNORE, STRICT)

    # 超过该比例即判定为严重损字，字段解析不得直接读取转码结果
    LOSSY_RATIO = 0.05

    def transcode(self, raw_bytes: bytes, source_encoding: str,
                  target_encoding: str, strategy: str) -> tuple[bool, bytes, int, str]:
        """执行真实转码，返回 (是否无损, 转码后字节, 不可映射字符数, 结论)。

        STRICT 策略下遇到不可映射字符直接失败，不产出半成品文本；
        REPLACE 用占位符替换并计数，IGNORE 直接丢弃并计数。
        """
        if strategy not in self.STRATEGIES:
            return False, b"", 0, f"替换策略「{strategy}」不在允许范围 {list(self.STRATEGIES)}"

        try:
            text = raw_bytes.decode(source_encoding)
        except (UnicodeDecodeError, LookupError) as exc:
            return False, b"", 0, (
                f"原始编码 {source_encoding} 解码失败: {exc}"
            )

        if strategy == self.STRICT:
            try:
                encoded = text.encode(target_encoding)
                return True, encoded, 0, (
                    f"{source_encoding}→{target_encoding} 严格转码无损，{len(encoded)} 字节"
                )
            except UnicodeEncodeError as exc:
                return False, b"", 0, (
                    f"STRICT 策略下存在不可映射字符，转码中止: {exc}"
                )

        errors = "replace" if strategy == self.REPLACE else "ignore"
        encoded = text.encode(target_encoding, errors=errors)
        roundtrip = encoded.decode(target_encoding, errors="replace")
        unmappable = sum(
            1 for original, converted in zip(text, roundtrip)
            if original != converted
        )
        if unmappable == 0:
            return True, encoded, 0, (
                f"{source_encoding}→{target_encoding} 转码完成，无不可映射字符"
            )
        return False, encoded, unmappable, (
            f"{source_encoding}→{target_encoding} 存在 {unmappable} 个不可映射字符"
            f"（策略 {strategy}）"
        )

    def record_transcode(self, norm_no: str, intake_batch: str, raw_bytes: bytes,
                         source_encoding: str, target_encoding: str,
                         strategy: str, elapsed_ms: int) -> tuple[bool, str, dict[str, Any] | None]:
        """执行转码并把真实计数写入转码记录，同时登记不可映射字符所在行。"""
        ok, encoded, unmappable, message = self.transcode(
            raw_bytes, source_encoding, target_encoding, strategy)

        rows = store.rows(self.MODULE)
        entry_id = max((int(r.get("id", 0)) for r in rows), default=0) + 1
        total_chars = len(raw_bytes.decode(source_encoding, errors="replace")) or 1
        lossy_ratio = unmappable / total_chars
        severe = unmappable > 0 and lossy_ratio > self.LOSSY_RATIO

        entry = {
            "id": entry_id,
            "status": ("已完成" if unmappable == 0 else "存在损字"),
            "pending": unmappable > 0,
            "abnormal": severe,
            "转码编号": norm_no,
            "关联批次": intake_batch,
            "原始编码": source_encoding,
            "目标编码": target_encoding,
            "不可映射字符数": str(unmappable),
            "替换策略": strategy,
            "转码后字节": str(len(encoded)),
            "转码耗时": str(elapsed_ms),
            "损字比例": f"{lossy_ratio:.4f}",
            "转码结论": message,
        }
        rows.append(entry)

        if severe:
            self._register_lossy_lines(intake_batch, raw_bytes, source_encoding,
                                       target_encoding, strategy)
            return False, (
                f"{message}，损字比例 {lossy_ratio:.2%} 超过 {self.LOSSY_RATIO:.0%}，"
                f"字段解析不得直接读取转码结果"
            ), dict(entry)
        return ok, message, dict(entry)

    def _register_lossy_lines(self, intake_batch: str, raw_bytes: bytes,
                              source_encoding: str, target_encoding: str,
                              strategy: str) -> list[str]:
        """把含不可映射字符的行登记为隔离行，隔离范围由损字位置决定。"""
        text = raw_bytes.decode(source_encoding, errors="replace")
        encoded = text.encode(target_encoding, errors="replace")
        decoded = encoded.decode(target_encoding, errors="replace")
        created: list[str] = []
        quarantine_rows = store.rows("row_quarantine")
        for index, (original_line, converted_line) in enumerate(
                zip(text.splitlines(), decoded.splitlines()), start=1):
            if original_line == converted_line:
                continue
            quarantine_no = f"RQ-{intake_batch}-enc-{index}"
            if any(r.get("隔离编号") == quarantine_no for r in quarantine_rows):
                continue
            entry_id = max((int(r.get("id", 0)) for r in quarantine_rows), default=0) + 1
            quarantine_rows.append({
                "id": entry_id, "status": "已隔离", "pending": True, "abnormal": True,
                "隔离编号": quarantine_no, "关联批次": intake_batch,
                "原始行号": str(index), "失败字段": "encoding",
                "失败原因": (
                    f"编码归一产生不可映射字符（{source_encoding}→{target_encoding}，"
                    f"策略 {strategy}）"
                ),
                "原始行文本": original_line, "复核结论": "",
                "隔离时间": "",
            })
            created.append(quarantine_no)
        return created

    def lossy_scope(self, norm_no: str) -> dict[str, Any]:
        """输出损字范围，供坏行隔离确定隔离行清单。"""
        intake_batch = ""
        unmappable = 0
        for row in store.rows(self.MODULE):
            if row.get("转码编号") == norm_no:
                intake_batch = str(row.get("关联批次") or "")
                text = str(row.get("不可映射字符数") or "0").strip()
                unmappable = int(text) if text.isdigit() else 0
                break
        isolated = [
            {"隔离编号": r.get("隔离编号"), "原始行号": r.get("原始行号")}
            for r in store.rows("row_quarantine")
            if r.get("关联批次") == intake_batch
            and "enc" in str(r.get("隔离编号") or "")
        ]
        return {
            "转码编号": norm_no,
            "关联批次": intake_batch,
            "不可映射字符数": unmappable,
            "隔离行数": len(isolated),
            "隔离行": isolated,
        }

    def blocks_field_parse(self, intake_batch: str) -> tuple[bool, str]:
        """严重损字的批次不得直接进入字段解析。"""
        for row in store.rows(self.MODULE):
            if row.get("关联批次") != intake_batch:
                continue
            if row.get("abnormal"):
                return True, (
                    f"批次 {intake_batch} 转码损字比例 {row.get('损字比例')} 超限，"
                    f"字段解析需先处理损字行"
                )
        for receipt in store.rows(LEDGER):
            if receipt.get("关联批次") != intake_batch:
                continue
            if receipt.get("abnormal") and self._open_lines(receipt):
                return True, (
                    f"批次 {intake_batch} 回执 {receipt.get('回执编号')} 损字比例 "
                    f"{receipt.get('损字比例')} 超阈值，候选不得直接交给字段解析，"
                    f"需先复核损字行"
                )
        return False, f"批次 {intake_batch} 转码结果可供字段解析读取"

    # ------------------------------------------------------------------
    # 逐文件转码回执：同名文件重传、断点续做与损字凭据留档
    # ------------------------------------------------------------------
    def record_file_bytes(
        self,
        file_key: str,
        raw_bytes: bytes,
        source_encoding: str,
        target_encoding: str,
        strategy: str,
        **options: Any,
    ) -> tuple[bool, str, dict[str, Any] | None]:
        """从单个文件当前位置续做：给接口层用的 (是否新建, 说明, 回执) 形态。"""
        before = len(store.rows(LEDGER))
        receipt = self.transcode_file(
            file_key, raw_bytes, source_encoding, target_encoding, strategy,
            **options)
        created = len(store.rows(LEDGER)) > before
        if receipt.get("status") == "未找到":
            return False, receipt.get("message", "转码回执未生成"), None
        message = (
            f"文件 {file_key} 已登记转码回执 {receipt['回执编号']}"
            if created else
            f"文件 {file_key} 已存在同内容回执 {receipt['回执编号']}，重复提交只记一次"
        )
        return True, message, receipt

    def resume_receipt(self, receipt_no: str, processed_lines: list[int],
                       resumed_from: int | None = None
                       ) -> tuple[bool, str, dict[str, Any] | None]:
        """从已确认行继续：兼容只给「从第几行继续」的调用方。"""
        receipt = self._find_receipt(receipt_no)
        if receipt is None:
            return False, f"转码回执 {receipt_no} 不存在", None
        lines = list(processed_lines)
        if resumed_from is not None:
            evidence_lines = {int(item["原始行号"]) for item in receipt.get("损字凭据") or []}
            lines.extend(n for n in evidence_lines if n < int(resumed_from))
        return self.mark_progress(receipt_no, lines, resumed_from)

    def transcode_file(
        self,
        file_key: str,
        raw_bytes: bytes,
        source_encoding: str,
        target_encoding: str,
        strategy: str,
        *,
        file_name: str = "",
        intake_batch: str = "",
        transcode_time: str = "",
        source_sha256: str = "",
        source_revision: int = 0,
    ) -> dict[str, Any]:
        """按文件登记一次转码尝试，返回可逐项续做的单文件回执。

        - 同一文件同内容重复提交（中断重启后重放）只记一次，直接复用旧回执；
        - 同名文件内容变化视为新修订版，旧回执与损字凭据原样保留；
        - 回执记录文件指纹、字节大小、失败行号与原始字符，供复核逐项处理。
        """
        raw_bytes = bytes(raw_bytes)
        digest = source_sha256 or hashlib.sha256(raw_bytes).hexdigest()
        ledger = store.rows(LEDGER)
        prior_of_file = [r for r in ledger if r.get("文件键") == file_key]
        same_content = next(
            (r for r in prior_of_file if r.get("原文指纹") == digest), None)
        if same_content is not None:
            return self.receipt_of(same_content["回执编号"], note="重复提交已复用原回执")

        revision = source_revision or (
            max((int(r.get("修订版次") or 0) for r in prior_of_file), default=0) + 1
        )

        text, decode_error = self._decode(raw_bytes, source_encoding)
        ok, encoded, unmappable, message = self.transcode(
            raw_bytes, source_encoding, target_encoding, strategy) if not decode_error else (
            False, b"", 0, decode_error)
        total_chars = len(text) or 1
        lossy_ratio = unmappable / total_chars
        severe = unmappable > 0 and lossy_ratio > self.LOSSY_RATIO

        receipt_no = f"EN-{self._slug(file_key)}-r{revision}-{digest[:8]}"
        lossy_lines = self._lossy_line_evidence(
            file_key, receipt_no, text, target_encoding, strategy) if unmappable else []
        if decode_error:
            status = "解码失败"
        else:
            status = "已完成" if unmappable == 0 else "存在损字"
        receipt = {
            "id": self._next_id(LEDGER),
            "status": status,
            "pending": unmappable > 0,
            "abnormal": severe,
            "回执编号": receipt_no,
            "文件键": file_key,
            "原始文件名": file_name or file_key,
            "关联批次": intake_batch,
            "修订版次": str(revision),
            "原文指纹": digest,
            "字节大小": str(len(raw_bytes)),
            "原始编码": source_encoding,
            "目标编码": target_encoding,
            "替换策略": strategy,
            "不可映射字符数": str(unmappable),
            "转码结论": message,
            "损字比例": f"{lossy_ratio:.4f}",
            "损字行号": ",".join(str(item["原始行号"]) for item in lossy_lines),
            "损字凭据": lossy_lines,
            "已处理行号": [],
            "回补行号": [],
            "解码失败": decode_error,
            "转码后文本": encoded.decode(target_encoding, errors="replace") if encoded else "",
            "转码时间": transcode_time,
            "重复提交": False,
        }
        ledger.append(receipt)
        return self._receipt_view(receipt)

    # ------------------------------------------------------------------
    # 续做游标：记录值班员处理到哪一行，重启后从该位置继续
    # ------------------------------------------------------------------
    def mark_progress(self, receipt_no: str, processed_lines: list[int],
                      resumed_from: int | None = None) -> tuple[bool, str, dict[str, Any] | None]:
        """推进单文件续做游标；已处理行重复登记只算一次。"""
        receipt = self._find_receipt(receipt_no)
        if receipt is None:
            return False, f"转码回执 {receipt_no} 不存在", None
        current = {int(n) for n in receipt.get("已处理行号") or []}
        for line in processed_lines:
            current.add(int(line))
        receipt["已处理行号"] = sorted(current)
        if resumed_from is not None:
            receipt["续做起点"] = str(resumed_from)
        if current:
            message = f"回执 {receipt_no} 续做游标推进至第 {max(current)} 行"
        elif resumed_from is not None:
            message = f"回执 {receipt_no} 续做游标已定位到第 {resumed_from} 行"
        else:
            message = f"回执 {receipt_no} 续做游标未变化"
        return True, message, self._receipt_view(receipt)

    def receipt_of(self, receipt_no: str, note: str = "") -> dict[str, Any]:
        """取单文件回执；找不到时返回带说明的空回执，不抛异常。"""
        receipt = self._find_receipt(receipt_no)
        if receipt is None:
            return {"回执编号": receipt_no, "status": "未找到", "message": note or "回执不存在"}
        view = self._receipt_view(receipt)
        if note:
            view["message"] = note
        return view

    def receipts_of_file(self, file_key: str) -> list[dict[str, Any]]:
        """同名文件的全部历史回执，旧修订版与损字凭据一律保留。"""
        return [
            self._receipt_view(r) for r in store.rows(LEDGER)
            if r.get("文件键") == file_key
        ]

    def file_summaries(self, intake_batch: str | None = None) -> list[dict[str, Any]]:
        """逐文件回执目录：给页面展示可继续操作，已接受的文件不再出现重跑入口。"""
        order: list[str] = []
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in store.rows(LEDGER):
            if intake_batch and row.get("关联批次") != intake_batch:
                continue
            key = str(row.get("文件键") or "")
            if key not in grouped:
                order.append(key)
                grouped[key] = []
            grouped[key].append(row)

        summaries: list[dict[str, Any]] = []
        for key in order:
            history = [self._receipt_view(r) for r in grouped[key]]
            latest = history[-1]
            # 已接受 = 最新修订版没有遗留待处理行（转码无损或损字行均已回补/废弃）
            accepted = not latest.get("可继续", False)
            summaries.append({
                "文件键": key,
                "原始文件名": latest.get("原始文件名", key),
                "关联批次": latest.get("关联批次", ""),
                "修订版数": len(history),
                "最新回执": latest,
                "已接受": accepted,
                "可重跑": not accepted,
                "可继续": latest.get("可继续", False),
                "待处理行号": latest.get("待处理行号", []),
                "历史证据": [self._evidence_summary(item) for item in history],
            })
        return summaries

    @staticmethod
    def _evidence_summary(receipt: dict[str, Any]) -> dict[str, Any]:
        """旧回执的错误证据摘要：修订版、损字行号与原始字符都保留。"""
        return {
            "回执编号": receipt.get("回执编号"),
            "修订版次": receipt.get("修订版次"),
            "状态": receipt.get("status"),
            "损字行号": receipt.get("损字行号", ""),
            "损字凭据": receipt.get("损字凭据") or [],
            "转码时间": receipt.get("转码时间", ""),
            "原文指纹": receipt.get("原文指纹", ""),
        }

    def receipt_batch(self, file_keys: list[str], *, limit: int = 3) -> dict[str, Any]:
        """批量续做：按文件逐个给出回执与下一个待处理位置，减少重复转码。"""
        items: list[dict[str, Any]] = []
        for file_key in file_keys:
            views = self.receipts_of_file(file_key)
            if not views:
                items.append({"文件键": file_key, "状态": "无回执",
                              "下一步": "需要先提交转码"})
                continue
            latest = views[-1]
            items.append({
                "文件键": file_key,
                "回执编号": latest["回执编号"],
                "状态": latest["status"],
                "下一步": self.next_step(latest["回执编号"]),
            })
        return {"items": items[:limit] if limit else items, "total": len(items)}

    def next_step(self, receipt_no: str) -> dict[str, Any]:
        """给出该文件下一个可继续的动作；已处理的行不会再次出现在待办里。"""
        receipt = self._find_receipt(receipt_no)
        if receipt is None:
            return {"动作": "无", "说明": f"回执 {receipt_no} 不存在"}
        pending = self._open_lines(receipt)
        if not pending:
            return {"动作": "转码已完成", "说明": "该文件没有待处理的损字行"}
        head = pending[0]
        return {
            "动作": "从失败行继续",
            "回执编号": receipt_no,
            "续做行号": head["原始行号"],
            "原始字符": head["原始字符"],
            "待处理行数": len(pending),
        }

    def resume_point(self, file_key: str) -> dict[str, Any]:
        """重启后从任一个入口继续：给出去重重算后的续做起点。"""
        views = self.receipts_of_file(file_key)
        if not views:
            return {"文件键": file_key, "可续做": False, "说明": "没有可续做的回执"}
        latest = views[-1]
        return {
            "文件键": file_key,
            "回执编号": latest["回执编号"],
            "可续做": latest["status"] != "已完成",
            "下一步": self.next_step(latest["回执编号"]),
            "历史修订数": len(views),
        }

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    @staticmethod
    def _slug(value: str) -> str:
        """把文件键压成可用于路径与编号的短标识，避免斜杠破坏接口路径。"""
        cleaned = "".join(
            char if char.isalnum() or char in "-_." else "-" for char in str(value))
        return cleaned.strip("-") or "file"

    def _next_id(self, module: str) -> int:
        rows = store.rows(module)
        return max((int(r.get("id", 0)) for r in rows), default=0) + 1

    def _find_receipt(self, receipt_no: str) -> dict[str, Any] | None:
        for row in store.rows(LEDGER):
            if row.get("回执编号") == receipt_no:
                return row
        return None

    @staticmethod
    def _decode(raw_bytes: bytes, encoding: str) -> tuple[str, str]:
        try:
            return raw_bytes.decode(encoding), ""
        except (UnicodeDecodeError, LookupError) as exc:
            return "", f"原始编码 {encoding} 解码失败: {exc}"

    def _lossy_line_evidence(self, file_key: str, receipt_no: str, text: str,
                             target_encoding: str, strategy: str) -> list[dict[str, Any]]:
        """逐行比对转码前后文本，把损字位置、原始字符留成凭据。"""
        evidence: list[dict[str, Any]] = []
        for index, original_line in enumerate(text.splitlines(), start=1):
            converted = original_line.encode(target_encoding, errors="replace").decode(
                target_encoding, errors="replace")
            if original_line == converted:
                continue
            chars: list[str] = []
            for original, after in zip(original_line, converted):
                if original != after and original not in chars:
                    chars.append(original)
            evidence.append({
                "原始行号": index,
                "原始字符": "".join(chars),
                "原始行文本": original_line,
                "转码后行文本": converted,
                "失败原因": (
                    f"编码归一产生不可映射字符（{target_encoding}，策略 {strategy}）"
                ),
                "文件键": file_key,
                "回执编号": receipt_no,
            })
        return evidence

    def _open_lines(self, receipt: dict[str, Any]) -> list[dict[str, Any]]:
        """仍待处理的损字行：既没被值班员标记处理，也没在坏行隔离里走到终态。

        终态按「回执 + 原行号」判定，同名新修订版的同号行不会被旧回执的处理结果吞掉；
        但同一来源文件同一原行在回补账本里已确认过的，后续修订版不再重复要求确认。
        """
        processed = {int(n) for n in receipt.get("已处理行号") or []}
        receipt_no = str(receipt.get("回执编号") or "")
        file_key = str(receipt.get("文件键") or "")
        confirmed_lines: set[int] = set()
        for entry in store.rows("_quarantine_reinstates"):
            if entry.get("文件键") != file_key:
                continue
            try:
                confirmed_lines.add(int(entry.get("原始行号")))
            except (TypeError, ValueError):
                continue
        terminal: set[int] = set()
        for row in store.rows("row_quarantine"):
            if receipt_no:
                if row.get("回执编号") != receipt_no:
                    continue
            elif row.get("文件键") != file_key:
                continue
            if str(row.get("status")) in ("已回补", "已废弃"):
                try:
                    terminal.add(int(row.get("原始行号")))
                except (TypeError, ValueError):
                    continue
        return [
            item for item in receipt.get("损字凭据") or []
            if int(item["原始行号"]) not in processed
            and int(item["原始行号"]) not in terminal
            and int(item["原始行号"]) not in confirmed_lines
        ]

    def _receipt_view(self, receipt: dict[str, Any]) -> dict[str, Any]:
        view = dict(receipt)
        open_lines = self._open_lines(receipt)
        view["待处理行号"] = [item["原始行号"] for item in open_lines]
        view["可继续"] = bool(open_lines)
        return view
