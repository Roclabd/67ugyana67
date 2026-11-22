/**
 * Выход ноды «Тест-доказательство (песочница)» (proof.sandbox) → модель экрана.
 * Значение порта proofs: {projectHash, error, results: [{findingId, class, test?, status, details?, source?}]}.
 * Незнакомое и битое не роняет экран: такие строки получают статус ERROR, а не «воспроизведено».
 */
export type ProofStatus = 'REPRODUCED' | 'NOT_REPRODUCED' | 'NOT_SUPPORTED' | 'ERROR' | 'TIMEOUT'

export interface ProofRow {
  findingId: string
  sastClass: string
  test?: string
  status: ProofStatus
  details?: string
  source?: string
}

export interface ProofReport {
  projectHash?: string
  error?: string
  rows: ProofRow[]
}

const STATUSES: ProofStatus[] = ['REPRODUCED', 'NOT_REPRODUCED', 'NOT_SUPPORTED', 'ERROR', 'TIMEOUT']

const text = (v: unknown) => (typeof v === 'string' && v.length > 0 ? v : undefined)

export function proofsFromOutput(output: unknown): ProofReport | null {
  if (typeof output !== 'object' || output === null) return null
  const proofs = (output as { proofs?: unknown }).proofs
  if (typeof proofs !== 'object' || proofs === null) return null
  const raw = (proofs as { results?: unknown }).results
  if (!Array.isArray(raw)) return null
  const rows = raw.filter((r): r is Record<string, unknown> => typeof r === 'object' && r !== null).map((r) => {
    const status = STATUSES.find((s) => s === r.status) ?? 'ERROR'
    return {
      findingId: text(r.findingId) ?? '—',
      sastClass: text(r.class) ?? '—',
      test: text(r.test),
      status,
      details: text(r.details) ?? (status === 'ERROR' && r.status !== 'ERROR' ? `Неизвестный статус: ${String(r.status)}` : undefined),
      source: text(r.source),
    }
  })
  const p = proofs as { projectHash?: unknown; error?: unknown }
  return { projectHash: text(p.projectHash), error: text(p.error), rows }
}
