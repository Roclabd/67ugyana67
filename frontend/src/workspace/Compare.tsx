import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { useApi } from '../api/useApi'
import type { CompareSide, Finding, RunSummary } from '../api/types'
import { AsyncView } from '../ui'
import { formatLocation } from '../ui/format'
import { Go, Heading, Panel, Risk } from './parts'
import { findingName, findingUrl, niceDate } from './data'
import { t } from '../i18n'

/** Ссылка «Сравнить с предыдущим»: берёт ближайший более ранний завершённый запуск того же сценария. */
export function CompareLink({ run, runs }: { run: RunSummary; runs: RunSummary[] }) {
  const prev = runs.find(
    (r) =>
      r.workflowId === run.workflowId &&
      r.runId !== run.runId &&
      Date.parse(r.startedAt) < Date.parse(run.startedAt) &&
      (r.status === 'SUCCESS' || r.status === 'PARTIAL'),
  )
  if (!prev) return null
  return (
    <Link className="text-link" to={`/compare?base=${encodeURIComponent(prev.runId)}&head=${encodeURIComponent(run.runId)}`}>
      {t('cmp.prev')}
    </Link>
  )
}

function sourceText(s: CompareSide): string {
  const where = s.kind === 'archive' ? 'ZIP' : (s.repoUrl ?? t('cmp.unknownSource'))
  const rev =
    s.commitSha ?? (s.inputHash ? (s.kind === 'archive' ? t('cmp.hash') : '') + s.inputHash.slice(0, 12) : t('cmp.unknownRev'))
  return `${where} · ${rev}${s.subdir ? ' · ' + s.subdir : ''}`
}

function SideCard({ title, s }: { title: string; s: CompareSide }) {
  return (
    <Panel title={title}>
      <div className="panel-body">
        <p>
          <Link className="text-link" to={'/runs/' + s.runId + '/report'}>
            {s.runId}
          </Link>{' '}
          · {niceDate(s.startedAt)}
        </p>
        <p className="mono">{sourceText(s)}</p>
        <p>
          {t('cmp.rules')} <code>{s.rulesVersion ?? t('cmp.noData')}</code>
        </p>
        <p>
          {t('cmp.coverage')}: {s.coverageStatus === 'COMPLETE' ? t('cmp.full') : s.coverageStatus === 'PARTIAL' ? t('cmp.part') : t('cmp.noData')}
        </p>
      </div>
    </Panel>
  )
}

function Group({ title, hint, items, runId }: { title: string; hint?: string; items: Finding[]; runId: string }) {
  return (
    <Panel title={title} action={<small>{items.length}</small>}>
      <div className="panel-body">
        {hint && <p className="muted">{hint}</p>}
        {items.length === 0 ? (
          <p className="empty">{t('cmp.none')}</p>
        ) : (
          <ul className="compare-list">
            {items.map((f) => (
              <li key={f.id}>
                <Risk level={f.severity} />{' '}
                <Link className="text-link" to={findingUrl(runId, f)}>
                  {findingName(f)}
                </Link>{' '}
                <span className="mono">{formatLocation(f.path, f.line, f.endLine)}</span>
                {f.class && <small> · {f.class}</small>}
              </li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  )
}

export function Compare() {
  const [q] = useSearchParams()
  const base = q.get('base') ?? '',
    head = q.get('head') ?? ''
  const query = useApi(() => (base && head ? api.compareRuns(base, head) : Promise.reject(new Error(t('cmp.need')))), [base, head])
  return (
    <AsyncView state={query.state} onRetry={query.reload}>
      {(r) => (
        <>
          <div className="inline-links">
            <Go to={'/runs/' + r.head.runId + '/report'}>{t('nav.toReport')} {r.head.runId}</Go>
          </div>
          <Heading title={t('cmp.title')} sub={`${r.base.runId} → ${r.head.runId}`} />
          {r.fixConfirmed ? (
            <div className="alert alert--info">
              <div className="alert__title">{t('cmp.fixOk')}</div>
              <div>{t('cmp.fixOkText')}</div>
            </div>
          ) : (
            <div className="alert alert--warn">
              <div className="alert__title">{t('cmp.notComparable')}</div>
              <ul>
                {r.reasons.map((x) => (
                  <li key={x}>{x}</li>
                ))}
              </ul>
              <div>{t('cmp.notFixed')}</div>
            </div>
          )}
          {r.notes?.map((x) => (
            <div key={x} className="alert alert--info"><div>{t('cmp.archiveNote')}: {x}</div></div>
          ))}
          <div className="detail-grid">
            <SideCard title={t('cmp.base')} s={r.base} />
            <SideCard title={t('cmp.head')} s={r.head} />
          </div>
          <Group title={t('cmp.added')} hint={t('cmp.addedHint')} items={r.added} runId={r.head.runId} />
          <Group title={t('cmp.unchanged')} items={r.unchanged} runId={r.head.runId} />
          <Group
            title={t('cmp.resolved')}
            hint={r.fixConfirmed ? t('cmp.fixOkDot') : t('cmp.fixNo')}
            items={r.resolved}
            runId={r.base.runId}
          />
        </>
      )}
    </AsyncView>
  )
}
