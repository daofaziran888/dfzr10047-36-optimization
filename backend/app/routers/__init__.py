"""业务路由汇总：通用资源路由 + 编码归一逐文件回执路由。"""
from __future__ import annotations

from app.routers import encoding_receipts, resource

# 顺序即注册顺序：固定路径的回执路由必须在 /api/{module}/{entry_id} 之前生效。
ROUTERS = [encoding_receipts, resource]
