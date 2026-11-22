import { describe, expect, it } from 'vitest'
import type { Finding } from '../../api/types'
import { nodeBadgeText, nodeFindings, sortBySeverity } from './nodeFindings'

const f = (id: string, severity: Finding['severity'], path = 'A.kt'): Finding =>
  ({ id, fingerprint: id, category: 'SAST', path, severity, rule: 'r', evidence: [] })

describe('nodeFindings', () => {
  it('достаёт находки из выхода и игнорирует мусор', () => {
    expect(nodeFindings({ findings: [f('a', 'HIGH'), 1, null] })).toHaveLength(1)
    expect(nodeFindings(undefined)).toEqual([])
    expect(nodeFindings({ findings: 'x' })).toEqual([])
  })
  it('бейдж: всего и критичные/высокие', () => {
    expect(nodeBadgeText([])).toBeNull()
    expect(nodeBadgeText([f('a', 'LOW')])).toBe('1')
    expect(nodeBadgeText([f('a', 'CRITICAL'), f('b', 'HIGH'), f('c', 'LOW'), f('d', 'LOW'), f('e', 'LOW')])).toBe('5 · 1 крит. · 1 выс.')
  })
  it('сортирует по серьёзности', () => {
    expect(sortBySeverity([f('a', 'LOW'), f('b', 'CRITICAL')]).map((x) => x.id)).toEqual(['b', 'a'])
  })
})
