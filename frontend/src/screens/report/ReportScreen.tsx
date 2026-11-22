import { Fragment, useState } from 'react'
import { api } from '../../api/client'
import { useApi } from '../../api/useApi'
import type { Finding, FindingCategory, Severity } from '../../api/types'
import { SEVERITIES } from '../../api/types'
import { AiSummary, FindingDetails, runAi, runFindings, SafeSpots } from '../../features/findings'
import {
  AsyncView,
  Card,
  CoverageBanner,
  Empty,
  Page,
  SecretMask,
  SeverityBadge,
  SeverityCounts as SeverityCountsDisplay,
  StatusBadge,
} from '../../ui'
import { formatLocation } from '../../ui/format'

export interface ReportScreenProps {
  runId: string
}

type CategoryFilter = FindingCategory | 'ALL'
type SeverityFilter = Severity | 'ALL'

const CATEGORIES: Array<{ value: CategoryFilter; label: string }> = [
  { value: 'ALL', label: 'Все категории' },
  { value: 'SECRET', label: 'SECRET' },
  { value: 'SCA', label: 'SCA' },
  { value: 'SAST', label: 'SAST' },
]

const SEVERITY_FILTERS: Array<{ value: SeverityFilter; label: string }> = [
  { value: 'ALL', label: 'Любая критичность' },
  { value: 'CRITICAL', label: 'От критичной' },
  { value: 'HIGH', label: 'От высокой' },
  { value: 'MEDIUM', label: 'От средней' },
  { value: 'LOW', label: 'От низкой' },
]

function compareFindings(a: Finding, b: Finding): number {
  const severityOrder = SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
  if (severityOrder !== 0) return severityOrder
  const pathOrder = a.path.localeCompare(b.path)
  if (pathOrder !== 0) return pathOrder
  return (a.line ?? 0) - (b.line ?? 0)
}

export function ReportScreen({ runId }: ReportScreenProps) {
  const run = useApi(() => api.getRun(runId), [runId])
  const [category, setCategory] = useState<CategoryFilter>('ALL')
  const [minimumSeverity, setMinimumSeverity] = useState<SeverityFilter>('ALL')
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null)

  return (
    <Page
      title={`Отчёт запуска ${runId}`}
      actions={
        run.state.status === 'ready' && run.state.data.report ? (
          <div className="row">
            <a className="btn" href={api.reportJsonUrl(runId)} download>JSON</a>
            <a className="btn" href={api.reportMdUrl(runId)} download>Markdown</a>
          </div>
        ) : null
      }
    >
      <AsyncView state={run.state} onRetry={run.reload}>
        {(data) => {
          const report = data.report
          if (!report) {
            return (
              <Card>
                <Empty text="Отчёт ещё не готов">
                  <p>Статус запуска: <StatusBadge status={data.status} /></p>
                </Empty>
              </Card>
            )
          }

          const severityCounts: Record<Severity, number> = {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
          }
          report.findings.forEach((finding) => {
            severityCounts[finding.severity] += 1
          })

          const categoryCounts: Record<FindingCategory, number> = {
            SECRET: 0,
            SCA: 0,
            SAST: 0,
          }
          report.findings.forEach((finding) => {
            categoryCounts[finding.category] += 1
          })

          const ai = runAi(data)
          const findings = runFindings(data)
          const filteredFindings = findings
            .filter((finding) => category === 'ALL' || finding.category === category)
            .filter((finding) => {
              if (minimumSeverity === 'ALL') return true
              return SEVERITIES.indexOf(finding.severity) <= SEVERITIES.indexOf(minimumSeverity)
            })
            .sort(compareFindings)

          const incompleteAnalyzers = Object.entries(report.coverage.byAnalyzer)
            .filter(([, coverage]) => coverage.status !== 'COMPLETE')

          return (
            <div className="stack">
              <div className="row">
                <StatusBadge status={data.status} />
                <span className="muted">Находок: {report.findings.length}</span>
                <span className="muted">Правила: {report.rulesVersion}</span>
              </div>

              <Card title="Сводка находок">
                <div className="stack">
                  <div className="row">
                    <strong>По критичности:</strong>
                    <SeverityCountsDisplay counts={severityCounts} />
                  </div>
                  <div className="row">
                    <span>SECRET: <strong>{categoryCounts.SECRET}</strong></span>
                    <span>SCA: <strong>{categoryCounts.SCA}</strong></span>
                    <span>SAST: <strong>{categoryCounts.SAST}</strong></span>
                  </div>
                </div>
              </Card>

              <Card title="Полнота анализа">
                <CoverageBanner
                  status={report.coverage.status}
                  details={
                    incompleteAnalyzers.length > 0 ? (
                      <div className="stack">
                        {incompleteAnalyzers.map(([nodeId, coverage]) => (
                          <div key={nodeId}>
                            <p><strong>Нода {nodeId}:</strong> <StatusBadge status={coverage.status} /></p>
                            {coverage.filesSkipped.length > 0 && (
                              <div>
                                <strong>Пропущенные файлы:</strong>
                                <ul>
                                  {coverage.filesSkipped.map((file, index) => (
                                    <li key={index}>
                                      <span className="mono">{formatLocation(file.path, file.line)}</span> — {file.reason}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            {coverage.unresolved.length > 0 && (
                              <div>
                                <strong>Не удалось разрешить:</strong>
                                <ul>
                                  {coverage.unresolved.map((item, index) => (
                                    <li key={index}>
                                      {item.subject ? `${item.subject}, ` : ''}
                                      <span className="mono">{formatLocation(item.path, item.line)}</span> — {item.reason}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : null
                  }
                />
                {incompleteAnalyzers.length === 0 && (
                  <p className="muted">Все анализаторы завершили проверку.</p>
                )}
              </Card>

              {ai ? (
                <AiSummary ai={ai} findings={findings} />
              ) : (
                <div className="alert alert--warn">
                  <div className="alert__title">Объяснения AI не получены</div>
                  Находки ниже получены анализаторами и от этого не зависят.
                </div>
              )}

              <Card title="Находки">
                <div className="row">
                  <label className="field">
                    <span className="field__label">Категория</span>
                    <select
                      className="select"
                      value={category}
                      onChange={(event) => setCategory(event.target.value as CategoryFilter)}
                    >
                      {CATEGORIES.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                  </label>
                  <label className="field">
                    <span className="field__label">Минимальная критичность</span>
                    <select
                      className="select"
                      value={minimumSeverity}
                      onChange={(event) => setMinimumSeverity(event.target.value as SeverityFilter)}
                    >
                      {SEVERITY_FILTERS.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                  </label>
                </div>

                {filteredFindings.length === 0 ? (
                  <Empty text="По выбранным фильтрам находок нет" />
                ) : (
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Критичность</th>
                        <th>Категория / класс</th>
                        <th>Название</th>
                        <th>Место</th>
                        <th>Секрет</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFindings.map((finding) => (
                        <Fragment key={finding.id}>
                          <tr
                            className="clickable"
                            onClick={() => setExpandedFinding((current) => current === finding.id ? null : finding.id)}
                          >
                            <td><SeverityBadge severity={finding.severity} /></td>
                            <td>
                              {finding.category}
                              <div className="muted">{finding.category === 'SCA' ? finding.advisoryId || '—' : finding.class || '—'}</div>
                            </td>
                            <td>{finding.title || finding.rule}</td>
                            <td className="mono">
                              {finding.category === 'SCA' ? (
                                <>
                                  {finding.group || '—'}:{finding.artifact || '—'}:{finding.version || '—'}
                                  <div>{formatLocation(finding.path, finding.line, finding.endLine)}</div>
                                </>
                              ) : formatLocation(finding.path, finding.line, finding.endLine)}
                            </td>
                            <td>{finding.category === 'SECRET' ? <SecretMask value={finding.secretMasked} /> : '—'}</td>
                          </tr>
                          {expandedFinding === finding.id && (
                            <tr>
                              <td colSpan={5}>
                                <FindingDetails finding={finding} />
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      ))}
                    </tbody>
                  </table>
                )}
              </Card>

              <SafeSpots coverage={report.coverage} />
            </div>
          )
        }}
      </AsyncView>
    </Page>
  )
}
