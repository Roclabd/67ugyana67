/**
 * Блок «Что проверяли» (запрос экспертов банка): по каждому анализатору — какие правила применены и как они работают,
 * со статусом покрытия. Данные — coverage.byAnalyzer отчёта; ничего не досчитывается.
 */
import type { ReportCoverage } from '../../api/types'
import { Card, StatusBadge } from '../../ui'
import { describeRules } from './catalog'
import { t } from '../../i18n'

type AnalyzerCoverage = ReportCoverage['byAnalyzer'][string] & { rules?: { id: string; title?: string; description?: string }[] }

export function ChecksApplied({ coverage, analyzerTitles = {} }: {
  coverage: ReportCoverage
  analyzerTitles?: Record<string, string>
}) {
  const analyzers = Object.entries(coverage.byAnalyzer) as [string, AnalyzerCoverage][]
  const total = analyzers.reduce((n, [, c]) => n + c.rulesApplied.length, 0)
  return (
    <Card title={t('chk.title', { a: analyzers.length, n: total })}>
      <div className="stack">
        {analyzers.map(([nodeId, c]) => (
          <div key={nodeId}>
            <div className="row" style={{ gap: 8 }}>
              <div className="finding__label">{analyzerTitles[nodeId] ?? nodeId}</div>
              <StatusBadge status={c.status} />
              <span className="muted">{t('chk.files')} {c.filesAnalyzed}</span>
            </div>
            <table className="table">
              <tbody>
                {describeRules(c.rulesApplied, c.rules).map((r) => (
                  <tr key={r.id}>
                    <td style={{ width: '30%' }}><strong>{r.title}</strong><div className="mono muted">{r.id}</div></td>
                    <td>{r.how ?? <span className="muted">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>
    </Card>
  )
}
