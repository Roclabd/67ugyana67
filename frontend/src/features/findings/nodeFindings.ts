import type { Finding, Severity } from '../../api/types'
import { t } from '../../i18n'

const ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

/** Находки, которые анализатор положил в выход своей ноды (output.findings). */
export function nodeFindings(output: unknown): Finding[] {
  const list = (output as { findings?: unknown } | null | undefined)?.findings
  return Array.isArray(list) ? list.filter((f): f is Finding => !!f && typeof f === 'object' && 'severity' in f) : []
}

/** Находки по убыванию серьёзности, затем по месту. */
export function sortBySeverity(findings: Finding[]): Finding[] {
  const rank = (s: Severity) => ORDER.indexOf(s)
  return [...findings].sort((a, b) => rank(a.severity) - rank(b.severity) || a.path.localeCompare(b.path) || (a.line ?? 0) - (b.line ?? 0))
}

/** Короткая подпись бейджа ноды: «5 · 1 крит.»; null, если находок нет. */
export function nodeBadgeText(findings: Finding[]): string | null {
  if (findings.length === 0) return null
  const crit = findings.filter((f) => f.severity === 'CRITICAL').length
  const high = findings.filter((f) => f.severity === 'HIGH').length
  const parts: string[] = [String(findings.length)]
  if (crit > 0) parts.push(t('nf.crit', { n: crit }))
  if (high > 0) parts.push(t('nf.high', { n: high }))
  return parts.join(' · ')
}
