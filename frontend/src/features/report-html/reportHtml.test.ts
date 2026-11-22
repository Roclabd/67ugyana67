import { describe, expect, it } from 'vitest'
import type { Report } from '../../api/types'
import { esc, reportHtml } from './reportHtml'

const report = {
  runId: 'run-1', inputHash: 'abc', rulesVersion: 'v1',
  coverage: { status: 'COMPLETE', byAnalyzer: { sast: { status: 'COMPLETE', filesAnalyzed: 12, filesSkipped: [], rulesApplied: ['sast.sql.taint-to-query'], unresolved: [], dismissed: [] } } },
  findings: [
    { id: 'f2', fingerprint: 'b', category: 'SECRET', class: 'password', path: 'A.kt', line: 4, severity: 'HIGH', rule: 'secret.password', evidence: [], secretMasked: 'pa****' },
    { id: 'f1', fingerprint: 'a', category: 'SAST', class: 'sql-injection', path: 'B.kt', line: 13, endLine: 14, severity: 'CRITICAL', rule: 'sast', title: '<script>x</script>',
      evidence: [{ path: 'B.kt', line: 13, note: 'источник' }] },
  ],
  ai: { status: 'NOT_RECEIVED', reason: 'LLM не настроена' },
} as unknown as Report

describe('reportHtml', () => {
  it('самодостаточный файл: находки по критичности, маска секрета, цепочка, покрытие с понятными правилами', () => {
    const html = reportHtml(report, { workflowName: 'Проверка' })
    expect(html.startsWith('<!doctype html>')).toBe(true)
    expect(html.indexOf('sql-injection')).toBeLessThan(html.indexOf('password'))
    expect(html).toContain('pa****')
    expect(html).toContain('<code>B.kt:13–14</code>')
    expect(html).toContain('SQL-инъекция')
    expect(html).toContain('Объяснения не получены: LLM не настроена')
    expect(html).not.toContain('<script>')
    expect(html).not.toMatch(/<link|src="http/)
  })

  it('неполный анализ — предупреждение', () => {
    const html = reportHtml({ ...report, coverage: { ...report.coverage, status: 'PARTIAL' } })
    expect(html).toContain('Анализ выполнен частично')
  })

  it('экранирует HTML', () => {
    expect(esc(`<a href="x">'&'</a>`)).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;')
  })
})

describe('reportHtml: замечания эксперта', () => {
  it('неполный анализ — с файлом и причиной; секреты в тестах — отдельным блоком', () => {
    const partial = {
      ...report,
      coverage: { status: 'PARTIAL', byAnalyzer: { sast: { status: 'PARTIAL', filesAnalyzed: 3, rulesApplied: [], unresolved: [],
        filesSkipped: [{ path: 'Broken.kt', line: 22, reason: 'Ошибка разбора' }],
        dismissed: [{ rule: 'secret.api-key', path: 'src/test/kotlin/Fixture.kt', line: 7, reason: 'excluded-source' },
          { rule: 'secret.scope', path: 'README.md', line: 1, reason: 'excluded-source' }] } } },
    } as unknown as Report
    const html = reportHtml(partial)
    expect(html).toContain('Broken.kt:22</code> — Ошибка разбора')
    expect(html).toContain('секреты в тестовом коде (1)')
    expect(html).toContain('src/test/kotlin/Fixture.kt:7')
    expect(html).not.toContain('README.md:1')
  })
})
