"""通用接口契约；模块字段由领域服务持有，不再为每个模块复制一份模型类。"""
from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PageResult(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int = 1
    size: int = 20


class ActionResult(BaseModel):
    ok: bool
    message: str
    entry: dict[str, Any] | None = None


class EntryPayload(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)
    remark: str | None = None


class ActionPayload(BaseModel):
    action: str
    remark: str | None = None


class ReceiptPayload(BaseModel):
    """单文件转码回执提交：按文件登记一次转码，同内容重放由服务端去重。"""
    file_key: str
    file_name: str = ""
    intake_batch: str = ""
    source_encoding: str
    target_encoding: str
    strategy: str = "REPLACE"
    content: str = ""
    transcode_time: str = ""
    source_revision: int = 0


class ReceiptResumePayload(BaseModel):
    """续做：从已确认行之后接着处理，重复行号只算一次。"""
    processed_lines: list[int] = Field(default_factory=list)
    resumed_from: int | None = None


class ReinstatePayload(BaseModel):
    """坏行隔离回补：可带复核生效后的修正取值写回解析批次。"""
    reviewer: str
    conclusion: str = ""
    review_time: str = ""
    corrected: dict[str, Any] = Field(default_factory=dict)
