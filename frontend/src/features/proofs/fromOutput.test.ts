import { describe, expect, it } from 'vitest'
import { proofsFromOutput } from './fromOutput'

describe('proofsFromOutput', () => {
  it('разбирает выход ноды proof.sandbox', () => {
    const r = proofsFromOutput({ proofs: { projectHash: 'a'.repeat(64), error: null, results: [
      { findingId: 'sast-1', class: 'route-authorization', test: 'Proof1', status: 'REPRODUCED', source: 'class Proof1' },
      { findingId: 'sast-2', class: 'tls-verification', status: 'NOT_SUPPORTED', details: 'Шаблона нет' },
    ] } })
    expect(r?.projectHash).toHaveLength(64)
    expect(r?.error).toBeUndefined()
    expect(r?.rows.map((x) => x.status)).toEqual(['REPRODUCED', 'NOT_SUPPORTED'])
    expect(r?.rows[0]).toMatchObject({ sastClass: 'route-authorization', test: 'Proof1', source: 'class Proof1' })
  })

  it('незнакомый статус — ошибка с пояснением, а не «воспроизведено»', () => {
    const r = proofsFromOutput({ proofs: { results: [{ findingId: 'x', class: 'sql-injection', status: 'MAYBE' }] } })
    expect(r?.rows[0].status).toBe('ERROR')
    expect(r?.rows[0].details).toContain('MAYBE')
  })

  it('чужой выход и мусор — null или пропуск строк', () => {
    expect(proofsFromOutput(undefined)).toBeNull()
    expect(proofsFromOutput({ findings: [] })).toBeNull()
    expect(proofsFromOutput({ proofs: { results: 'нет' } })).toBeNull()
    expect(proofsFromOutput({ proofs: { results: [null, 5, { status: 'REPRODUCED' }] } })?.rows).toHaveLength(1)
  })
})
