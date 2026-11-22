import { describe, expect, it } from 'vitest'
import { qualityFromOutput, qualityFromValue } from './fromOutput'

const block = {
  version: 1,
  status: 'ISSUES',
  message: 'Найдено замечаний: 1.',
  filesAnalyzed: 2,
  filesByLanguage: { python: 2 },
  truncated: false,
  summary: { total: 1, byKind: { 'functional-defect': 1 } },
  diagnostics: [
    { kind: 'functional-defect', rule: 'python.defect.mutable-default', language: 'python', path: 'a.py', line: 1, column: 20, message: 'm', confidence: 'PROVEN' },
    { kind: 'unknown-kind', path: 'x', line: 1, message: 'bad' },
  ],
  skipped: [],
  unsupported: [],
}

describe('qualityFromOutput', () => {
  it('читает блок версии 1 и отбрасывает битые замечания', () => {
    const q = qualityFromOutput({ quality: block })
    expect(q?.status).toBe('ISSUES')
    expect(q?.diagnostics).toHaveLength(1)
    expect(q?.diagnostics[0].line).toBe(1)
  })

  it('не падает на старом отчёте, чужой версии и мусоре', () => {
    expect(qualityFromOutput(undefined)).toBeNull()
    expect(qualityFromOutput({})).toBeNull()
    expect(qualityFromValue({ ...block, version: 2 })).toBeNull()
    expect(qualityFromValue({ ...block, status: 'WHAT' })).toBeNull()
    expect(qualityFromValue('x')).toBeNull()
  })
})
