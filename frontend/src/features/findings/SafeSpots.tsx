/**
 * Проверенные и отклонённые безопасные места (киллер-фича 5 — работа с ловушками):
 * анализатор показывает, что он видел кандидата и почему это не уязвимость (параметризация, ${ENV}, версия вне диапазона).
 * Данные — coverage.byAnalyzer[*].dismissed отчёта; ничего не досчитывается на фронте.
 */
import type { ReportCoverage } from '../../api/types'
import { Card, Empty } from '../../ui'
import { formatLocation } from '../../ui/format'
import { isTestSecret } from './testSecrets'
import { t } from '../../i18n'

/** SECRET (C4) отдаёт причину кодом; SAST и SCA — уже фразой. Неизвестный код показывается как есть. */
const REASON_TEXT: Record<string, string> = {
  get 'environment-reference'() { return t('dismiss.environment-reference') },
  get 'non-literal-fallback'() { return t('dismiss.non-literal-fallback') },
  get placeholder() { return t('dismiss.placeholder') },
  get 'test-source'() { return t('dismiss.test-source') },
  get 'excluded-source'() { return t('dismiss.excluded-source') },
}

export function SafeSpots({ coverage, analyzerTitles = {} }: {
  coverage: ReportCoverage
  /** id ноды → название для заголовка группы (например, из каталога и графа). */
  analyzerTitles?: Record<string, string>
}) {
  const attention = Object.values(coverage.byAnalyzer).flatMap((c) => c.dismissed.filter(isTestSecret))
  const groups = Object.entries(coverage.byAnalyzer)
    .map(([id, c]) => [id, c.dismissed.filter((d) => !isTestSecret(d))] as const)
    .filter(([, list]) => list.length > 0)
  const total = groups.reduce((n, [, list]) => n + list.length, 0)
  return (
    <Card title={t('safe.title', { n: total })}>
      {attention.length > 0 && (
        <div className="alert alert--warn" style={{ marginBottom: 12 }}>
          <div className="alert__title">{t('safe.attention', { n: attention.length })}</div>
          {t('safe.attentionText')}
          <ul className="coverage-list">
            {attention.map((d, i) => (
              <li key={i} className="mono">{formatLocation(d.path, d.line)} · {d.rule.replace(/^secret\./, '')}</li>
            ))}
          </ul>
        </div>
      )}
      {total === 0 ? (
        attention.length > 0 ? null : <Empty text={t('safe.empty')} />
      ) : (
        <div className="stack">
          <p className="muted" style={{ margin: 0 }}>
            {t('safe.intro')}
          </p>
          {groups.map(([nodeId, list]) => (
            <div key={nodeId}>
              <div className="finding__label">{analyzerTitles[nodeId] ?? nodeId}</div>
              <table className="table safe-spots">
                <tbody>
                  {list.map((d, i) => (
                    <tr key={i}>
                      <td className="mono">{formatLocation(d.path, d.line)}</td>
                      <td>{REASON_TEXT[d.reason] ?? d.reason}</td>
                      <td className="mono muted">{d.rule}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
