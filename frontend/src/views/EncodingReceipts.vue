<template>
  <section class="receipt-panel" data-testid="encoding-receipts">
    <header class="receipt-head">
      <div>
        <h3>逐文件转码回执</h3>
        <p class="page-desc">
          按文件查看已确认的转码结果与损字证据；同名新文件不会覆盖旧凭据，已接受的文件不再提供重跑。
        </p>
      </div>
      <button class="btn" type="button" data-testid="reload-receipts" @click="reload">
        刷新回执
      </button>
    </header>

    <table class="data-table">
      <thead>
        <tr>
          <th>来源文件</th>
          <th>关联批次</th>
          <th>修订版</th>
          <th>最新状态</th>
          <th>待处理行号</th>
          <th>历史损字证据</th>
          <th>可执行操作</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="file in files"
          :key="file.文件键"
          :data-testid="`receipt-file-${file.文件键}`"
          :data-accepted="String(file.已接受)"
        >
          <td>{{ file.原始文件名 }}</td>
          <td>{{ file.关联批次 || '—' }}</td>
          <td>R{{ file.修订版数 }}</td>
          <td>{{ file.最新回执.status }}</td>
          <td>{{ file.待处理行号.length ? file.待处理行号.join('、') : '—' }}</td>
          <td>
            <span v-if="!file.历史证据.length">—</span>
            <button
              v-for="evidence in file.历史证据"
              :key="evidence.回执编号"
              class="link evidence-link"
              type="button"
              :data-testid="`evidence-${evidence.回执编号}`"
              @click="openReview(evidence.回执编号)"
            >
              R{{ evidence.修订版次 }} · 行 {{ evidence.损字行号 || '—' }}
            </button>
          </td>
          <td class="row-actions">
            <button
              v-if="file.可继续"
              class="link"
              type="button"
              :data-testid="`continue-${file.文件键}`"
              @click="continueFile(file)"
            >
              从失败行继续
            </button>
            <button
              class="link"
              type="button"
              :data-testid="`open-receipt-${file.文件键}`"
              @click="openReview(file.最新回执.回执编号)"
            >
              查看本次采用结果
            </button>
            <span v-if="file.已接受" class="accepted-tag" :data-testid="`accepted-${file.文件键}`">
              已接受，不提供重跑
            </span>
          </td>
        </tr>
        <tr v-if="!files.length">
          <td colspan="7" class="empty-state">暂无逐文件转码回执，先提交一份文件转码。</td>
        </tr>
      </tbody>
    </table>

    <p v-if="receiptMessage" class="receipt-message" data-testid="receipt-message">
      {{ receiptMessage }}
    </p>

    <div v-if="review" class="modal-backdrop" data-testid="receipt-review-modal">
      <div class="modal">
        <h3>回执 {{ review.receiptNo }} · 逐原行复核结果</h3>
        <p class="page-desc">
          每个原行只给一份此次真正采用的转码结果或回补结果；原行号与原始字符保留不变。
        </p>
        <table class="data-table">
          <thead>
            <tr>
              <th>原行号</th>
              <th>原始字符</th>
              <th>采用的转码结果</th>
              <th>隔离状态</th>
              <th>回补结果 / 复核结论</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in review.items" :key="item.原始行号">
              <td>{{ item.原始行号 }}</td>
              <td>{{ item.原始字符 || '—' }}</td>
              <td>{{ item.采用的转码结果 || '—' }}</td>
              <td>{{ item.隔离状态 }}</td>
              <td>{{ item.回补结果 || item.复核结论 || '—' }}</td>
            </tr>
            <tr v-if="!review.items.length">
              <td colspan="5" class="empty-state">该回执没有损字行，转码结果已全部采用。</td>
            </tr>
          </tbody>
        </table>
        <div class="page-actions">
          <button class="btn" type="button" data-testid="close-review" @click="review = null">关闭</button>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'

import { listReceipts, loadReceiptReview, resumeReceipt } from '@/api/backend-service'
import type { FileSummary, ReceiptReviewItem } from '@/data/types'

const files = ref<FileSummary[]>([])
const receiptMessage = ref('')
const review = ref<{ receiptNo: string; items: ReceiptReviewItem[] } | null>(null)

async function reload() {
  receiptMessage.value = ''
  try {
    files.value = (await listReceipts()).items
  } catch (error) {
    receiptMessage.value = error instanceof Error ? error.message : '回执读取失败'
  }
}

async function continueFile(file: FileSummary) {
  receiptMessage.value = ''
  const nextLine = file.待处理行号[0]
  try {
    const result = await resumeReceipt(file.最新回执.回执编号, [], nextLine)
    receiptMessage.value = result.message
    await reload()
    if (result.ok && nextLine !== undefined) {
      await openReview(file.最新回执.回执编号)
    }
  } catch (error) {
    receiptMessage.value = error instanceof Error ? error.message : '续做失败'
  }
}

async function openReview(receiptNo: string) {
  receiptMessage.value = ''
  try {
    review.value = await loadReceiptReview(receiptNo)
  } catch (error) {
    receiptMessage.value = error instanceof Error ? error.message : '复核结果读取失败'
  }
}

onMounted(reload)

defineExpose({ reload })
</script>

<style scoped>
.receipt-panel { margin-top: 20px; }
.receipt-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.evidence-link { display: block; text-align: left; font-size: 12px; }
.accepted-tag { color: var(--muted); font-size: 12px; }
.receipt-message { color: #1f6feb; font-size: 12px; margin: 8px 0 0; }
</style>
