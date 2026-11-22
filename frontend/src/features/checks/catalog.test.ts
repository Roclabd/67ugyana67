import { describe, expect, it } from 'vitest'
import { CHECKS, describeRules } from './catalog'

describe('describeRules', () => {
  it('известное правило — понятное название и суть алгоритма', () => {
    const [row] = describeRules(['sast.sql.taint-to-query'])
    expect(row.title).toBe('SQL-инъекция')
    expect(row.how).toContain('параметра запроса')
  })

  it('описание с сервера важнее каталога, неизвестный id — как есть', () => {
    const rows = describeRules(['secret.password', 'x.new-rule'], [{ id: 'secret.password', title: 'Пароли (сервер)' }])
    expect(rows[0].title).toBe('Пароли (сервер)')
    expect(rows[0].how).toBe(CHECKS['secret.password'].how)
    expect(rows[1]).toEqual({ id: 'x.new-rule', title: 'x.new-rule', how: undefined })
  })

  it('в каталоге есть все правила, которые сейчас отдают анализаторы', () => {
    const current = ['secret.password', 'secret.api-key', 'secret.configuration-token', 'secret.secret-fallback', 'secret.recoverable-token',
      'sca.maven-advisory', 'sast.sql.taint-to-query', 'sast.tls.trust-all', 'sast.cors.any-origin-with-credentials',
      'sast.route.public-sensitive-route', 'sast.idor.read-by-id-without-owner']
    expect(current.filter((id) => !CHECKS[id])).toEqual([])
  })
})
