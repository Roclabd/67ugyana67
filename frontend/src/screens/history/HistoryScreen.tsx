import { useState } from 'react'
import { api } from '../../api/client'
import { useApi } from '../../api/useApi'
import type { RunStatus, RunSummary } from '../../api/types'
import {
  AsyncView,
  Card,
  Empty,
  Page,
  SeverityCounts,
  StatusBadge,
} from '../../ui'
import { formatDateTime, formatDuration } from '../../ui/format'
import { t } from '../../i18n'

type StatusFilter = RunStatus | 'ALL'

const STATUS_FILTERS: Array<{ value: StatusFilter; label: string }> = [
  { value: 'ALL', get label() { return t('hs.allStatuses') } },
  { value: 'SUCCESS', get label() { return t('st.SUCCESS') } },
  { value: 'PARTIAL', get label() { return t('st.PARTIAL') } },
  { value: 'FAILED', get label() { return t('st.FAILED') } },
  { value: 'RUNNING', get label() { return t('st.RUNNING') } },
]

function findingTotal(run: RunSummary): number {
  return Object.values(run.counts).reduce((total, count) => total + count, 0)
}

function comparisonLabel(current: RunSummary, previous?: RunSummary): string {
  if (!previous) return '—'
  if (current.coverageStatus !== 'COMPLETE' || previous.coverageStatus !== 'COMPLETE') {
    return t('hs.notComparable')
  }

  const difference = findingTotal(current) - findingTotal(previous)
  if (difference > 0) return `+${difference}`
  if (difference < 0) return `−${Math.abs(difference)}`
  return '0'
}

export interface HistoryScreenProps {
  /** Если задан — только запуски этого сценария. */
  workflowId?: string
  onOpenRun: (runId: string) => void
  onOpenReport: (runId: string) => void
}

export function HistoryScreen({ workflowId, onOpenRun, onOpenReport }: HistoryScreenProps) {
  const runs = useApi(() => api.listRuns(workflowId), [workflowId])
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('ALL')

  return (
    <Page
      title={t('hs.title')}
      subtitle={workflowId ? t('hs.onlyWf', { id: workflowId }) : undefined}
      actions={<button className="btn" onClick={runs.reload}>{t('hs.refresh')}</button>}
    >
      <AsyncView state={runs.state} onRetry={runs.reload}>
        {(items) => {
          if (items.length === 0) {
            return (
              <Card>
                <Empty text={t('hs.none')} />
              </Card>
            )
          }

          // API отдаёт список от новых запусков к старым. Идём с конца,
          // чтобы для каждой записи найти следующую, более старую запись сценария.
          const previousByRunId = new Map<string, RunSummary>()
          const nextOlderByWorkflow = new Map<string, RunSummary>()
          for (let index = items.length - 1; index >= 0; index -= 1) {
            const item = items[index]
            const previous = nextOlderByWorkflow.get(item.workflowId)
            if (previous) previousByRunId.set(item.runId, previous)
            nextOlderByWorkflow.set(item.workflowId, item)
          }

          const visibleRuns = items.filter((item) => statusFilter === 'ALL' || item.status === statusFilter)

          return (
            <Card title={t('nav.runs')}>
              <div className="row">
                <label className="field">
                  <span className="field__label">{t('hs.runStatus')}</span>
                  <select
                    className="select"
                    value={statusFilter}
                    onChange={(event) => setStatusFilter(event.target.value as StatusFilter)}
                  >
                    {STATUS_FILTERS.map((option) => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                </label>
              </div>

              {visibleRuns.length === 0 ? (
                <Empty text={t('hs.noStatus')} />
              ) : (
                <table className="table">
                  <thead>
                    <tr>
                      <th>{t('hs.thTime')}</th>
                      <th>{t('tpl.workflow')}</th>
                      <th>{t('run.titleShort')}</th>
                      <th>{t('cmp.coverage')}</th>
                      <th>{t('nav.findings')}</th>
                      <th>{t('hs.thChange')}</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {visibleRuns.map((item) => {
                      const previous = previousByRunId.get(item.runId)
                      const comparison = comparisonLabel(item, previous)
                      return (
                        <tr
                          key={item.runId}
                          className="clickable"
                          onClick={() => onOpenRun(item.runId)}
                        >
                          <td>
                            {formatDateTime(item.startedAt)}
                            <div className="muted">{formatDuration(item.startedAt, item.finishedAt)}</div>
                          </td>
                          <td>{item.workflowName || item.workflowId}</td>
                          <td><StatusBadge status={item.status} /></td>
                          <td><StatusBadge status={item.coverageStatus} /></td>
                          <td>
                            <SeverityCounts counts={item.counts} />
                            {item.coverageStatus !== 'COMPLETE' && (
                              <div className="muted">{t('hs.incomplete')}</div>
                            )}
                          </td>
                          <td className={comparison === t('hs.notComparable') ? 'muted' : undefined}>
                            {comparison}
                          </td>
                          <td>
                            <button
                              className="btn"
                              type="button"
                              disabled={item.status === 'RUNNING'}
                              onClick={(event) => {
                                event.stopPropagation()
                                onOpenReport(item.runId)
                              }}
                            >
                              {t('dash.report')}
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </Card>
          )
        }}
      </AsyncView>
    </Page>
  )
}
