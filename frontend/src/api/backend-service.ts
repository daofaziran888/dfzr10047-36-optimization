import { request } from './client'
import { moduleMeta } from '@/data/modules'
import type {
  ActionResult,
  EntryRow,
  FileSummary,
  OverviewResult,
  PageResult,
  ReceiptReviewItem,
  TranscodeReceipt,
} from '@/data/types'

export { moduleMeta }

export async function listEntries(
  key: string,
  filters: Record<string, string> = {},
): Promise<PageResult> {
  const query = new URLSearchParams(filters).toString()
  const response = await request(`/api/${key}?${query}`)
  if (!response.ok) throw new Error('业务数据读取失败')
  return await response.json()
}

export async function createEntry(
  key: string,
  values: Record<string, string>,
): Promise<ActionResult> {
  const response = await request(`/api/${key}`, {
    method: 'POST',
    body: JSON.stringify({ values }),
  })
  return await response.json()
}

export async function runAction(
  key: string,
  id: number,
  action: string,
): Promise<ActionResult> {
  const response = await request(`/api/${key}/${id}/actions`, {
    method: 'POST',
    body: JSON.stringify({ action }),
  })
  return await response.json()
}

export async function downloadEntries(
  key: string,
  filters: Record<string, string> = {},
): Promise<void> {
  const query = new URLSearchParams(filters).toString()
  const response = await request(`/api/${key}/export?${query}`)
  if (!response.ok) throw new Error('业务数据导出失败')
  const url = URL.createObjectURL(await response.blob())
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `${key}.csv`
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}

export async function loadOverview(): Promise<OverviewResult> {
  const response = await request('/api/overview')
  if (!response.ok) throw new Error('运营概览读取失败')
  return await response.json()
}

export async function listReceipts(intakeBatch?: string): Promise<{ items: FileSummary[]; total: number }> {
  const query = intakeBatch ? `?intake_batch=${encodeURIComponent(intakeBatch)}` : ''
  const response = await request(`/api/encoding_norm/receipts${query}`)
  if (!response.ok) throw new Error('逐文件转码回执读取失败')
  return await response.json()
}

export async function submitReceipt(payload: {
  file_key: string
  file_name?: string
  intake_batch?: string
  source_encoding: string
  target_encoding: string
  strategy?: string
  content: string
  transcode_time?: string
}): Promise<ActionResult & { entry?: TranscodeReceipt | null }> {
  const response = await request('/api/encoding_norm/receipts', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
  return await response.json()
}

export async function resumeReceipt(
  receiptNo: string,
  processedLines: number[],
  resumedFrom?: number,
): Promise<ActionResult & { entry?: TranscodeReceipt | null }> {
  const response = await request(`/api/encoding_norm/receipts/${encodeURIComponent(receiptNo)}/resume`, {
    method: 'POST',
    body: JSON.stringify({ processed_lines: processedLines, resumed_from: resumedFrom }),
  })
  return await response.json()
}

export async function loadReceiptReview(receiptNo: string): Promise<{
  receiptNo: string
  items: ReceiptReviewItem[]
}> {
  const response = await request(`/api/encoding_norm/receipts/${encodeURIComponent(receiptNo)}/review`)
  if (!response.ok) throw new Error('回执复核结果读取失败')
  const payload = await response.json()
  return { receiptNo, items: payload.items ?? [] }
}

export async function loadReceiptNext(receiptNo: string): Promise<Record<string, unknown>> {
  const response = await request(`/api/encoding_norm/receipts/${encodeURIComponent(receiptNo)}/next`)
  if (!response.ok) throw new Error('回执续做位置读取失败')
  return await response.json()
}
