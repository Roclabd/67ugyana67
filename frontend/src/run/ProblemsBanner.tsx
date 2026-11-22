import type { RunDelivery, RunStatus } from '../api/types'
import { findProblems, type ProblemNodeRun } from './problems'
import { t } from '../i18n'

/**
 * Сбой доставки уведомлений: показывается отдельно от анализа. Отчёт при этом готов и открывается,
 * статус и покрытие запуска от доставки не зависят.
 */
export function DeliveryBanner(props: {
  delivery: RunDelivery | undefined
  hasReport: boolean
  onSelect: (nodeId: string) => void
  onOpenReport: () => void
}) {
  const failed = props.delivery?.failed ?? []
  if (failed.length === 0) return null
  return (
    <div className="alert alert--warn">
      <div className="alert__title">{t('prob.notDelivered')}</div>
      <p className="muted">
        {t('prob.indep')}
        {props.hasReport && (
          <>
            {' '}
            <button type="button" className="problems__link" onClick={props.onOpenReport}>{t('find.openReport')}</button>
          </>
        )}
      </p>
      <ul className="problems__list">
        {failed.map((f) => (
          <li key={f.nodeId}>
            <button type="button" className="problems__link" onClick={() => props.onSelect(f.nodeId)}>
              {t('prob.stage', { name: f.nodeId })} ({f.type})
            </button>
            : {f.error}
          </li>
        ))}
      </ul>
    </div>
  )
}

export function ProblemsBanner(props: {
  order: { id: string; title: string; ai?: boolean; delivery?: boolean }[]
  nodes: Record<string, ProblemNodeRun>
  runStatus: RunStatus | null
  onSelect: (nodeId: string) => void
  onShowAll?: (nodeIds: string[]) => void
}) {
  const problems = findProblems(props.order, props.nodes)
  if (problems.length === 0) return null
  const failed = props.runStatus === 'FAILED' || problems.some((problem) => problem.status === 'FAILED')
  const heading = failed ? t('prob.whereBroke') : t('prob.remarks')
  const rootCount = problems.filter((problem) => problem.primary).length
  const impacted = problems.filter((problem) => problem.status === 'SKIPPED').length
  const names = new Map(props.order.map(({ id, title }) => [id, title]))
  return (
    <section className={`alert problems ${failed ? 'alert--error' : 'alert--warn'}`} aria-label={heading}>
      <div className="problems__heading">
        <div className="alert__title" aria-live="polite">
          {heading}{rootCount > 1 ? t('prob.primaryCount', { n: rootCount }) : ''}
          {impacted > 0 && <span className="problems__impact-count">{t('prob.impacted')} {impacted}</span>}
        </div>
        {props.onShowAll && (
          <button type="button" className="btn" onClick={() => props.onShowAll?.(problems.map((p) => p.nodeId))}>
            {failed ? t('prob.showAllErrors') : t('prob.showRemarks')}
          </button>
        )}
      </div>
      <ul className="problems__list">
        {problems.map((p) => (
          <li key={p.nodeId}>
            {p.primary && <strong className="problems__primary">{t('prob.primary')} </strong>}
            <button type="button" className="problems__link" onClick={() => props.onSelect(p.nodeId)}>
              {t('prob.stage', { name: p.title })}
            </button>
            {': '}{p.reason}
            {p.causeIds.length > 0 && (
              <span className="problems__causes">
                {' · '}{p.status === 'FAILED' ? t('prob.duringFailure') : t('prob.cause')}
                {p.causeIds.map((id, index) => (
                  <span key={id}>
                    {index > 0 && ', '}
                    <button type="button" className="problems__link" onClick={() => props.onSelect(id)}>
                      «{names.get(id) ?? id}»
                    </button>
                  </span>
                ))}
              </span>
            )}
          </li>
        ))}
      </ul>
    </section>
  )
}
