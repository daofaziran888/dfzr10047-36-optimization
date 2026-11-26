"""编码归一逐文件回执接口：批量续做、断点续做、损字隔离消费与逐项复核结果。

固定路径必须排在通用 `/{module}/{entry_id}` 之前注册，否则 receipts 会被
当成 entry_id 解析而报 422。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from app.schemas import ActionResult, ReceiptPayload, ReceiptResumePayload
from app.services.encoding_norm import EncodingNormService
from app.services.row_quarantine import RowQuarantineService

router = APIRouter(prefix="/api", tags=["编码归一续做"])


def _encoding() -> EncodingNormService:
    return EncodingNormService()


@router.get("/encoding_norm/receipts")
def list_receipts(intake_batch: str | None = Query(default=None)) -> dict[str, Any]:
    """逐文件回执目录：已接受的文件不再给出重跑入口。"""
    items = _encoding().file_summaries(intake_batch)
    return {"items": items, "total": len(items)}


@router.post("/encoding_norm/receipts", response_model=ActionResult)
def submit_receipt(payload: ReceiptPayload) -> ActionResult:
    """提交单文件转码；同内容重复提交只记一次并复用原回执。"""
    try:
        raw_bytes = payload.content.encode(payload.source_encoding)
    except (UnicodeEncodeError, LookupError) as exc:
        return ActionResult(
            ok=False,
            message=f"提交内容无法按声明编码 {payload.source_encoding} 还原为字节: {exc}")
    ok, message, receipt = _encoding().record_file_bytes(
        payload.file_key,
        raw_bytes,
        payload.source_encoding,
        payload.target_encoding,
        payload.strategy,
        file_name=payload.file_name,
        intake_batch=payload.intake_batch,
        transcode_time=payload.transcode_time,
        source_revision=payload.source_revision,
    )
    return ActionResult(ok=ok, message=message, entry=receipt)


@router.get("/encoding_norm/receipts/{receipt_no}")
def get_receipt(receipt_no: str) -> dict[str, Any]:
    """单文件回执：保留旧错误证据与当前可继续的操作。"""
    return _encoding().receipt_of(receipt_no)


@router.post("/encoding_norm/receipts/{receipt_no}/resume", response_model=ActionResult)
def resume_receipt(receipt_no: str, payload: ReceiptResumePayload) -> ActionResult:
    """从已确认行继续；重复行号只算一次。"""
    ok, message, receipt = _encoding().resume_receipt(
        receipt_no, payload.processed_lines, payload.resumed_from)
    return ActionResult(ok=ok, message=message, entry=receipt)


@router.get("/encoding_norm/receipts/{receipt_no}/review")
def get_receipt_review(receipt_no: str) -> dict[str, Any]:
    """逐原行给出此次真正采用的转码结果或回补结果。"""
    return RowQuarantineService().receipt_review_result(receipt_no)


@router.get("/encoding_norm/receipts/{receipt_no}/next")
def get_next_step(receipt_no: str) -> dict[str, Any]:
    """该文件下一个可继续的位置，供值班员逐项处理。"""
    return _encoding().next_step(receipt_no)


@router.post("/encoding_norm/receipts/{receipt_no}/consume", response_model=ActionResult)
def consume_receipt(receipt_no: str, quarantine_time: str = Query(default="")) -> ActionResult:
    """坏行隔离消费损字隔离清单，重复消费只补建缺失行。"""
    result = RowQuarantineService().consume_lossy_receipt(receipt_no, quarantine_time)
    created = result.get("created") or []
    ok = bool(created) or result.get("skipped", 0) > 0
    return ActionResult(ok=ok, message=result.get("message", ""), entry=result)
