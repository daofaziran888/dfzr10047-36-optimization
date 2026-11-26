/** 纯前端数据层的公共类型：与全栈版后端返回的结构保持一致，换回后端时页面不用改。 */

export type EntryRow = {
  id: number
  status: string
  pending: boolean
  abnormal: boolean
  [field: string]: string | number | boolean
}

export type ModuleMeta = {
  key: string
  name: string
  entity: string
  desc: string
  fields: string[]
  statuses: string[]
  actions: string[]
  actionTargets: Record<string, string>
  metrics: string[]
}

export type PageResult = {
  items: EntryRow[]
  total: number
  page: number
  size: number
}

export type ActionResult = {
  ok: boolean
  message: string
  entry?: Record<string, unknown> | null
}

export type LossyEvidence = {
  原始行号: number
  原始字符: string
  原始行文本: string
  转码后行文本: string
  失败原因: string
  文件键: string
  回执编号: string
}

export type TranscodeReceipt = {
  回执编号: string
  文件键: string
  原始文件名: string
  关联批次: string
  修订版次: string
  原文指纹: string
  字节大小: string
  原始编码: string
  目标编码: string
  替换策略: string
  不可映射字符数: string
  损字比例: string
  损字行号: string
  损字凭据: LossyEvidence[]
  待处理行号: number[]
  可继续: boolean
  已处理行号: number[]
  转码结论: string
  转码时间: string
  status: string
  pending: boolean
  abnormal: boolean
}

export type FileSummary = {
  文件键: string
  原始文件名: string
  关联批次: string
  修订版数: number
  最新回执: TranscodeReceipt
  已接受: boolean
  可重跑: boolean
  可继续: boolean
  待处理行号: number[]
  历史证据: {
    回执编号: string
    修订版次: string
    状态: string
    损字行号: string
    损字凭据: LossyEvidence[]
    转码时间: string
  }[]
}

export type ReceiptReviewItem = {
  原始行号: string
  原始字符: string
  采用的转码结果: string
  隔离状态: string
  回补结果: string
  复核结论: string
}

export type OverviewResult = {
  cards: { label: string; value: number }[]
  modules: { name: string; created: number; pending: number; abnormal: number }[]
}
