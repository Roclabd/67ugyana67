/** Общие компоненты находок (D7). Экран отчёта A-2 импортирует их отсюда. */
import type { Finding, FindingAi, Run, ReportAi } from '../../api/types'

export { AiBlock, EvidenceChain, FindingDetails } from './FindingDetails'
export { FindingList } from './FindingList'
export { findingLabel } from './findingLabel'
export { AiSummary } from './AiSummary'
export { SafeSpots } from './SafeSpots'

/**
 * Раздел `ai` запуска. Источник — report.ai; пока сервер кладёт туда только статус, берём тот же раздел
 * из выхода ноды ai.explain (порт explanation: {text, ai, usefulness}) — это тоже ответ сервера, прошедший валидатор.
 */
export function runAi(run: Run): ReportAi | null {
  const fromReport = run.report?.ai
  if (fromReport?.summary || fromReport?.validator) return fromReport
  for (const n of run.nodeRuns) {
    const explanation = (n.output as { explanation?: { ai?: ReportAi } } | undefined)?.explanation
    if (explanation?.ai?.status) return explanation.ai
  }
  return fromReport ?? null
}

/**
 * Находки отчёта с полем `ai`. Набор и порядок — строго из report.findings (анализаторы).
 * Пока сервер собирает отчёт только из выходов анализаторов, поле `ai` берётся из выхода ноды ai.explain
 * того же запуска по отпечатку находки; находки без пары остаются как есть.
 */
export function runFindings(run: Run): Finding[] {
  const findings = run.report?.findings ?? []
  if (findings.every((f) => f.ai)) return findings
  const aiByFingerprint = new Map<string, FindingAi>()
  for (const n of run.nodeRuns) {
    const out = (n.output as { findings?: Finding[] } | undefined)?.findings
    if (!Array.isArray(out)) continue
    for (const f of out) if (f.ai && f.fingerprint) aiByFingerprint.set(f.fingerprint, f.ai)
  }
  return findings.map((f) => (f.ai ? f : { ...f, ai: aiByFingerprint.get(f.fingerprint) }))
}
