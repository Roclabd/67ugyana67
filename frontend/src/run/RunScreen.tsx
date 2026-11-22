/**
 * Страница запуска: итог от сервера (GET /api/runs/{id}) плюс живые события SSE, пока запуск идёт.
 * Итоговый статус и покрытие берутся из ответа сервера, а не из того, что фронт насчитал по событиям.
 */
import { useEffect } from 'react'
import { api } from '../api/client'
import { useApi } from '../api/useApi'
import { useLiveRun } from '../store'
import { AsyncView, Card, CoverageBanner, Page, SeverityCounts, StatusBadge } from '../ui'
import { formatDateTime, formatDuration } from '../ui/format'
import { NodeRunPanel } from './NodeRunPanel'
import { DeliveryBanner, ProblemsBanner } from './ProblemsBanner'
import { AiSummary, FindingList, runAi, runFindings, SafeSpots } from '../features/findings'
import { RouteMapView, runRoutes } from '../features/routes'
import { ChecksApplied } from '../features/checks/ChecksApplied'
import { qualityFromValue } from '../features/quality/fromOutput'
import { QualityResults } from '../features/quality/QualityResults'
import { reportHtml } from '../features/report-html/reportHtml'
import { t } from '../i18n'

export interface RunScreenProps {
  runId: string
  onOpenReport: (runId: string) => void
  onOpenWorkflow: (workflowId: string) => void
}

export function RunScreen({ runId, onOpenReport, onOpenWorkflow }: RunScreenProps) {
  const run = useApi(() => api.getRun(runId), [runId])
  const live = useLiveRun()
  const liveStatus = live.runId === runId ? live.status : null

  // Пока идёт — подписываемся на события; по завершении перечитываем итог с сервера.
  useEffect(() => {
    if (run.state.status === 'ready' && run.state.data.status === 'RUNNING' && live.runId !== runId) live.watch(runId, run.state.data.workflowId, run.state.data.workflowVersion)
  }, [run.state, live, runId])
  useEffect(() => {
    if (liveStatus && liveStatus !== 'RUNNING') run.reload()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveStatus])

  const ready = run.state.status === 'ready' ? run.state.data : null
  const quality = qualityFromValue(ready?.report?.quality)
  const qualityOnly = !!quality && Object.keys(ready?.report?.coverage.byAnalyzer ?? {}).length === 0
  const savedNodes = Object.fromEntries((ready?.nodeRuns ?? []).map((node) => [node.nodeId, node]))
  const nodes = live.runId === runId && ready?.status === 'RUNNING'
    ? { ...savedNodes, ...Object.fromEntries(Object.values(live.nodes).map((node) => [node.nodeId, { ...savedNodes[node.nodeId], ...node }])) }
    : savedNodes
  const actions = ready && (
    <>
      <button className="btn" onClick={() => {
        live.restore(ready)
        onOpenWorkflow(ready.workflowId)
      }}>{t('run.toWorkflow')}</button>
      {ready.report && !qualityOnly && (
        <button className="btn" title={t('run.htmlTitle')} onClick={() => {
          const url = URL.createObjectURL(new Blob([reportHtml(ready.report!, { workflowName: ready.workflowName ?? undefined, finishedAt: ready.finishedAt ?? undefined })], { type: 'text/html' }))
          const a = Object.assign(document.createElement('a'), { href: url, download: `report-${ready.runId.slice(0, 8)}.html` })
          a.click()
          setTimeout(() => URL.revokeObjectURL(url), 1000)
        }}>{t('sum.html')}</button>
      )}
      <button className="btn btn--primary" disabled={!ready.report} onClick={() => onOpenReport(ready.runId)}>{t('dash.report')}</button>
    </>
  )

  return (
    <Page title={ready?.workflowName ? t('run.title', { name: ready.workflowName }) : t('run.titleShort')} actions={actions}>
      <AsyncView state={run.state} onRetry={run.reload}>
        {(r) => {
          const selectNode = (nodeId: string) => {
            const el = document.getElementById(`run-node-${nodeId}`)
            if (el instanceof HTMLDetailsElement) el.open = true
            el?.scrollIntoView({ behavior: 'smooth', block: 'center' })
          }
          const deliveryIds = new Set((r.delivery?.failed ?? []).map((f) => f.nodeId))
          const analysisRuns = Object.values(nodes).filter((n) => !deliveryIds.has(n.nodeId))
          return (
          <div className="stack">
            <ProblemsBanner
              order={analysisRuns.map((n) => ({ id: n.nodeId, title: n.nodeId, ai: /^ai([-_.]|$)/i.test(n.nodeId) }))}
              nodes={Object.fromEntries(analysisRuns.map((n) => [n.nodeId, n]))}
              runStatus={liveStatus ?? r.status}
              onSelect={selectNode}
            />
            <DeliveryBanner delivery={r.delivery} hasReport={!!r.report} onSelect={selectNode} onOpenReport={() => onOpenReport(r.runId)} />
            <Card>
              <div className="row">
                <StatusBadge status={r.status} />
                {qualityOnly ? <span>{t('run.qualityCheck')}</span> : (
                  <>
                    <span>{t('run.coverage')}</span>
                    <StatusBadge status={r.coverageStatus} />
                    <SeverityCounts counts={r.counts} labelled />
                  </>
                )}
                <span className="muted">
                  {formatDateTime(r.startedAt)} · {formatDuration(r.startedAt, r.finishedAt)} · {t('run.workflowV')}{r.workflowVersion} · <span className="mono" title={r.runId}>{r.runId.slice(0, 8)}</span>
                </span>
              </div>
            </Card>
            {!qualityOnly && <CoverageBanner status={r.status === 'RUNNING' ? null : r.coverageStatus} />}
            {r.report && !qualityOnly && (() => {
              const ai = runAi(r)
              const findings = runFindings(r)
              const routes = runRoutes(r, findings)
              return (
                <>
                  {ai && <AiSummary ai={ai} findings={findings} />}
                  <Card title={t('run.findings', { n: r.report.findings.length })}>
                    {r.report.findings.length === 0 ? (
                      <p className="muted">
                        {r.report.coverage.status === 'COMPLETE' ? t('run.noFindingsFull') : t('run.noFindingsPartial')}
                      </p>
                    ) : (
                      <FindingList findings={findings} />
                    )}
                  </Card>
                  {routes && <RouteMapView map={routes} findings={findings} />}
                  {r.report.coverage.byAnalyzer && <SafeSpots coverage={r.report.coverage} />}
                  {r.report.coverage.byAnalyzer && <ChecksApplied coverage={r.report.coverage} />}
                </>
              )
            })()}
            {quality && <Card title={t('sum.quality')}><QualityResults quality={quality} /></Card>}
            <Card title={t('sum.stages')}>
              <div className="stack">
                {Object.keys(nodes).length === 0 && <p className="muted">{t('run.noNodes')}</p>}
                {Object.values(nodes).map((n) => (
                    <details key={n.nodeId} id={`run-node-${n.nodeId}`} className="card">
                      <summary className="row">
                        <span className="mono">{n.nodeId}</span>
                        <StatusBadge status={n.status} />
                      </summary>
                      <NodeRunPanel node={n} />
                    </details>
                ))}
              </div>
            </Card>
          </div>
          )
        }}
      </AsyncView>
    </Page>
  )
}
