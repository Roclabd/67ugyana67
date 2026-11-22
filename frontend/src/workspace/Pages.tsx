import { useState } from 'react'
import './pages-steel.css'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  BookOpen,
  Check,
  Download,
  FileArchive,
  FileCode2,
  FileJson,
  FolderGit2,
  ChevronRight,
  FolderPlus,
  GitBranch,
  GitFork,
  Network,
  Send,
  Search,
  Settings2,
  Shield,
  Workflow as Flow,
} from 'lucide-react'
import { api, USE_MOCKS } from '../api/client'
import { useApi } from '../api/useApi'
import { SEVERITIES, type Finding, type Run } from '../api/types'
import { AiBlock, AiSummary, EvidenceChain, runAi, runFindings, SafeSpots } from '../features/findings'
import { ChecksApplied } from '../features/checks/ChecksApplied'
import { RouteMapView, runRoutes } from '../features/routes'
import { reportHtml } from '../features/report-html/reportHtml'
import { qualityFromValue } from '../features/quality/fromOutput'
import { QualityResults } from '../features/quality/QualityResults'
import { AsyncView, CoverageBanner } from '../ui'
import { formatDuration } from '../ui/format'
import { Panel, Go, Risk, State, Heading } from './parts'
import {
  download,
  engineNames,
  findingName,
  findingUrl,
  lastReport,
  niceDate,
  severityNames,
  sorted,
  total,
  type Project,
} from './data'
import githubMark from '../ui/github.svg'
import { Trend } from './Dashboard'
import { NewProject } from './NewProject'
import { CompareLink } from './Compare'
import { t, locale } from '../i18n'

function Filter({
  value,
  change,
  hint = t('common.search'),
}: {
  value: string
  change: (v: string) => void
  hint?: string
}) {
  return (
    <label className="filter-input">
      <Search size={17} />
      <input value={value} placeholder={hint} aria-label={hint} onChange={(e) => change(e.target.value)} />
    </label>
  )
}
export function Projects({ projects, choose }: { projects: Project[]; choose: (p: Project) => void }) {
  const [params, setParams] = useSearchParams()
  const [search, setSearch] = useState('')
  const [risk, setRisk] = useState('all')
  const filtered = projects.filter(
    (p) =>
      (p.name + ' ' + p.repo + ' ' + (p.kind === 'archive' ? 'zip' : '')).toLowerCase().includes(search.toLowerCase()) &&
      (risk === 'all' || (lastReport(p)?.counts.CRITICAL ?? 0) > 0),
  )
  return (
    <>
      <Heading
        title={t('nav.projects')}
        sub={t('proj.sub')}
        action={
          (
            <button className="primary" onClick={() => setParams({ new: '1' })}>
              <FolderPlus size={17} />
              {t('proj.add')}
            </button>
          )
        }
      />
      {params.get('new') === '1' && (
        <NewProject close={() => setParams({}, { replace: true })} created={choose} />
      )}
      <div className="filters">
        <Filter value={search} change={setSearch} hint={t('proj.findPh')} />
        <select aria-label={t('proj.filter')} value={risk} onChange={(e) => setRisk(e.target.value)}>
          <option value="all">{t('proj.all')}</option>
          <option value="critical">{t('proj.withCritical')}</option>
        </select>
      </div>
      <div className="steel-register project-register">
        <table>
          <thead>
            <tr>
              <th>{t('proj.thProject')}</th>
              <th>{t('proj.branch')}</th>
              <th>{t('proj.lastCheck')}</th>
              <th>{t('dash.critical')}</th>
              <th>
                <span className="visually-hidden">{t('proj.action')}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((p) => (
              <tr key={p.id}>
                <td>
                  <div className="project-name">
                    {p.kind === 'archive' ? <FileArchive size={19} aria-label={t('proj.kindZip')} /> : <FolderGit2 size={19} aria-label={t('proj.kindRepo')} />}
                    <div>
                      <h2>{p.name}</h2>
                      <small>{p.kind === 'archive' ? t('proj.kindZip') : p.repo.replace(/^https?:\/\//, '') || t('proj.local')}</small>
                    </div>
                  </div>
                </td>
                <td data-label={t('proj.branch')}>
                  <code>{p.branch}</code>
                </td>
                <td data-label={t('proj.checkLabel')}>{p.runs[0] ? niceDate(p.runs[0].startedAt) : t('proj.noRuns')}</td>
                <td data-label={t('dash.critical')}>
                  <b className={lastReport(p)?.counts.CRITICAL ? 'critical-value' : ''}>
                    {lastReport(p)?.counts.CRITICAL ?? '—'}
                  </b>
                </td>
                <td>
                  <button className="quiet-action" onClick={() => choose(p)}>
                    {t('proj.open')} <ChevronRight size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!filtered.length && <p className="empty">{t('proj.none')}</p>}
    </>
  )
}
export function RoutesForProject({ project }: { project: Project }) {
  const [params, setParams] = useSearchParams()
  // По умолчанию — последний запуск сценария с нодой «Карта маршрутов»: у остальных карты нет, экран был бы пустым.
  const mapFlows = new Set(project.flows.filter(w => w.nodes.some(n => n.type === 'output.route-map')).map(w => w.id))
  const runId = params.get('run') || (project.runs.find(r => mapFlows.has(r.workflowId)) ?? project.runs[0])?.runId
  return (
    <>
      <Heading title={t('nav.routes')} sub={t('routes.sub')}
        action={<div className="inline-links"><Go to="/scenarios">{t('routes.workflows')}</Go><Go to="/templates">{t('sf.templates.n')}</Go></div>} />
      {runId ? <>
        <label className="row">{t('routes.run')}
          <select value={runId} onChange={e => setParams({ run: e.target.value })}>
            {!project.runs.some(run => run.runId === runId) && <option value={runId}>{runId} · {t('routes.selected')}</option>}
            {project.runs.map(run => <option key={run.runId} value={run.runId}>
              {niceDate(run.startedAt)} · {run.workflowName ?? run.workflowId} · {run.runId.slice(0, 8)}
            </option>)}
          </select>
        </label>
        <LoadedRun key={runId} id={runId}>{run => {
          const findings = runFindings(run)
          const map = runRoutes(run, findings)
          return map ? <RouteMapView map={map} findings={findings} /> :
            <p className="empty">{t('routes.noMap')} <Go to="/templates">{t('routes.openTpl')}</Go></p>
        }}</LoadedRun>
      </> : <p className="empty">{t('routes.noRuns')}</p>}
    </>
  )
}

export function RepositoriesSettings() {
  const repositories = useApi(api.getRepositories, [])
  return (
    <Panel title={t('repos.title')} action={<Go to="/projects?new=1">{t('repos.add')}</Go>}>
      <div className="panel-body">
        <AsyncView state={repositories.state} onRetry={repositories.reload}>{settings => settings.repositories.length ?
          <ul>{settings.repositories.map(repo => <li key={repo}><code>{repo}</code></li>)}</ul> :
          <p>{t('repos.empty')}</p>
        }</AsyncView>
      </div>
    </Panel>
  )
}

export function Library({ p }: { p: Project }) {
  const [q, setQ] = useState(''),
    [filter, setFilter] = useState('all')
  const flows = p.flows.filter(
    (w) =>
      w.name.toLowerCase().includes(q.toLowerCase()) &&
      (filter === 'all' || w.nodes.some((n) => n.type === 'analyzer.' + filter)),
  )
  return (
    <>
      <Heading
        title={t('lib.title')}
        sub={t('lib.sub')}
        action={<Go to="/templates">{t('lib.teamTpl')}</Go>}
      />
      <div className="filters">
        <Filter value={q} change={setQ} hint={t('lib.searchPh')} />
        <select aria-label={t('dash.thAnalyzer')} value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="all">{t('lib.allAnalyzers')}</option>
          {Object.entries(engineNames).map(([k, v]) => (
            <option key={k} value={k.toLowerCase()}>
              {v}
            </option>
          ))}
        </select>
      </div>
      <div className="steel-library">
        {flows.map((w) => (
          <article key={w.id} className="route-entry">
            <Flow size={20} />
            <div className="route-main">
              <h2>{w.name}</h2>
              <div className="route-meta">
                <code>v{w.version}</code>
                <span>{w.nodes.length} {t('dash.stages')}</span>
                <span>
                  {Object.entries(engineNames)
                    .filter(([k]) => w.nodes.some((n) => n.type === 'analyzer.' + k.toLowerCase()))
                    .map(([, v]) => v)
                    .join(' · ')}
                </span>
              </div>
              <details>
                <summary>{t('lib.composition')}</summary>
                <ol className="route-stages">
                  {w.nodes.map((n) => (
                    <li key={n.id}>
                      <code>{n.type}</code>
                    </li>
                  ))}
                </ol>
              </details>
            </div>
            <Link className="quiet-action" to={'/workflows/' + w.id}>
              <Settings2 size={15} />
              {t('lib.configure')}
            </Link>
          </article>
        ))}
      </div>
      {!flows.length && <p className="empty">{t('lib.none')}</p>}
      <Go to="/workflows">{t('lib.manage')}</Go>
    </>
  )
}
export function History({ p, reports = false }: { p: Project; reports?: boolean }) {
  const [q, setQ] = useState(''),
    [status, setStatus] = useState('')
  const items = p.runs.filter(
    (r) =>
      (!reports || r.status === 'PARTIAL' || r.status === 'SUCCESS') &&
      (!status || r.status === status) &&
      ((r.workflowName ?? r.workflowId) + ' ' + r.runId).toLowerCase().includes(q.toLowerCase()),
  )
  return (
    <>
      <Heading
        title={reports ? t('nav.reports') : t('hist.title')}
        sub={reports ? t('hist.subReports') : t('hist.sub')}
        action={<Go to="/history/all">{t('hist.allWorkflows')}</Go>}
      />
      <div className="filters">
        <Filter value={q} change={setQ} hint={t('hist.findPh')} />
        <select aria-label={t('hist.state')} value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">{t('hist.allStates')}</option>
          <option value="SUCCESS">{t('state.SUCCESS')}</option>
          <option value="PARTIAL">{t('state.PARTIAL')}</option>
          {!reports && (
            <>
              <option value="RUNNING">{t('state.RUNNING')}</option>
              <option value="FAILED">{t('state.FAILED')}</option>
            </>
          )}
        </select>
      </div>
      <Panel
        title={reports ? t('hist.archive') : t('hist.log')}
        action={<small>{t('hist.records')} {items.length}</small>}
      >
        {reports ? (
          <div className="steel-register report-archive">
            <table>
              <thead>
                <tr>
                  <th>{t('hist.thReport')}</th>
                  <th>{t('cmp.coverage')}</th>
                  <th>{t('dash.critical')}</th>
                  <th>{t('dash.allFindings')}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.runId}>
                    <td>
                      <Link className="archive-title" to={'/runs/' + r.runId + '/report'}>
                        {r.workflowName || r.workflowId}
                      </Link>
                      <small>
                        {r.runId} · {niceDate(r.startedAt)}{' '}
                        <CompareLink run={r} runs={p.runs} />
                      </small>
                    </td>
                    <td data-label={t('cmp.coverage')}>
                      {r.coverageStatus === 'COMPLETE'
                        ? t('cov.full')
                        : r.coverageStatus === 'PARTIAL'
                          ? t('cov.part')
                          : t('cov.none')}
                    </td>
                    <td data-label={t('dash.critical')}>
                      <span className={r.counts.CRITICAL ? 'critical-value' : ''}>{r.counts.CRITICAL}</span>
                    </td>
                    <td data-label={t('dash.allFindings')}>{total(r.counts)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="records">
            {items.map((r) => (
              <Link key={r.runId} to={'/runs/' + r.runId}>
                <span className="record-icon">
                  <GitFork />
                </span>
                <span className="record-title">
                  <b>{r.workflowName || r.workflowId}</b>
                  <small>
                    {r.runId} · {niceDate(r.startedAt)}
                  </small>
                </span>
                <span>{formatDuration(r.startedAt, r.finishedAt)}</span>
                <State value={r.status} />
              </Link>
            ))}
          </div>
        )}
        {!items.length && <p className="empty">{t('hist.empty')}</p>}
      </Panel>
    </>
  )
}
type ReviewMap = Record<string, boolean>
function readReviews(): ReviewMap {
  try {
    return JSON.parse(localStorage.getItem('workflow.review.v1') || '{}')
  } catch {
    return {}
  }
}
function reviewed(r: string, f: Finding) {
  return !!readReviews()[r + '|' + f.fingerprint]
}
export function Findings({ defaultRun, lastReportRun }: { defaultRun?: string; lastReportRun?: string }) {
  const [sp] = useSearchParams()
  const id = sp.get('run') ?? defaultRun
  if (!id) return <p className="empty">{t('find.noReports')}</p>
  return <LoadedRun id={id}>{(run) => <FindingList run={run} lastReportRun={lastReportRun} />}</LoadedRun>
}
function FindingList({ run, lastReportRun }: { run: Run; lastReportRun?: string }) {
  if (run.report) return <Registry run={run} />
  return (
    <p className="empty">
      {t('find.runNoReport')} <Go to={'/runs/' + run.runId}>{t('find.openRun')}</Go>
      {lastReportRun && lastReportRun !== run.runId && <> · <Go to={'/findings?run=' + lastReportRun}>{t('find.lastReport')}</Go></>}
    </p>
  )
}
function Registry({ run }: { run: Run }) {
  const [sp, setSp] = useSearchParams()
  const q = sp.get('q') ?? '',
    risk = sp.get('severity') ?? '',
    cat = sp.get('analyzer') ?? '',
    order = sp.get('sort') ?? 'risk'
  function change(k: string, v: string) {
    const s = new URLSearchParams(sp)
    if (v) s.set(k, v)
    else s.delete(k)
    s.set('run', run.runId)
    setSp(s, { replace: true })
  }
  const found = sorted(runFindings(run)).filter(
    (f) =>
      (!risk || risk === f.severity) &&
      (!cat || cat === f.category) &&
      [f.title, f.id, f.path, f.advisoryId, f.rule].join(' ').toLowerCase().includes(q.toLowerCase()),
  )
  if (order === 'name') found.sort((a, b) => findingName(a).localeCompare(findingName(b), locale()))
  return (
    <>
      <Heading
        title={t('nav.findings')}
        sub={run.runId + ' · ' + niceDate(run.startedAt)}
        action={<Go to={'/runs/' + run.runId + '/report'}>{t('find.openReport')}</Go>}
      />
      <div className="filters">
        <Filter value={q} change={(v) => change('q', v)} hint={t('find.filterPh')} />
        <select aria-label={t('find.severity')} value={risk} onChange={(e) => change('severity', e.target.value)}>
          <option value="">{t('find.anySeverity')}</option>
          {SEVERITIES.map((k) => (
            <option key={k} value={k}>
              {severityNames[k]}
            </option>
          ))}
        </select>
        <select aria-label={t('dash.thAnalyzer')} value={cat} onChange={(e) => change('analyzer', e.target.value)}>
          <option value="">{t('lib.allAnalyzers')}</option>
          {Object.entries(engineNames).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <select aria-label={t('find.sort')} value={order} onChange={(e) => change('sort', e.target.value)}>
          <option value="risk">{t('find.bySeverity')}</option>
          <option value="name">{t('find.byName')}</option>
        </select>
      </div>
      <Panel title={t('find.registry')} action={<small>{t('hist.records')} {found.length}</small>}>
        <div className="findings-table compact-table">
          <table>
            <thead>
              <tr>
                {[t('dash.thFinding'), t('find.severity'), t('dash.thAnalyzer'), t('find.thLocation'), t('find.thStatus')].map((s) => (
                  <th key={s}>{s}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {found.map((f) => (
                <tr key={f.id}>
                  <td>
                    <Link to={findingUrl(run.runId, f) + (sp.size ? '?' + sp.toString() : '')}>
                      {findingName(f)}
                    </Link>
                    <small>{f.advisoryId ?? f.class ?? f.rule}</small>
                  </td>
                  <td>
                    <Risk level={f.severity} />
                  </td>
                  <td>{engineNames[f.category]}</td>
                  <td title={f.path}>
                    {f.path.split('/').pop()}:{f.line ?? '—'}
                  </td>
                  <td>{reviewed(run.runId, f) ? t('find.seen') : t('find.new')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!found.length && <p className="empty">{t('find.nomatch')}</p>}
      </Panel>
    </>
  )
}
export function LoadedRun({ id, children }: { id: string; children: (r: Run) => React.ReactNode }) {
  const query = useApi(() => api.getRun(id), [id])
  return (
    <AsyncView state={query.state} onRetry={query.reload}>
      {children}
    </AsyncView>
  )
}
export function FindingPage() {
  const { runId = '', findingId = '' } = useParams()
  return (
    <LoadedRun id={runId}>
      {(run) => {
        const f = runFindings(run).find((f) => f.id === findingId)
        return f ? (
          <Detail key={f.id} run={run} f={f} />
        ) : (
          <p className="empty">{t('find.missing')}</p>
        )
      }}
    </LoadedRun>
  )
}
function Detail({ run, f }: { run: Run; f: Finding }) {
  const [query] = useSearchParams()
  const listQuery = new URLSearchParams(query)
  listQuery.set('run', run.runId)
  const [seen, setSeen] = useState(() => reviewed(run.runId, f)),
    [error, setError] = useState('')
  function toggle() {
    try {
      localStorage.setItem(
        'workflow.review.v1',
        JSON.stringify({ ...readReviews(), [run.runId + '|' + f.fingerprint]: !seen }),
      )
      setSeen(!seen)
    } catch {
      setError(t('find.saveFail'))
    }
  }
  return (
    <>
      <div className="inline-links">
        <Go to={'/findings?' + listQuery.toString()}>{t('dash.allFindings')}</Go>
        <Go to={'/runs/' + run.runId + '/report'}>{t('nav.toReport')} {run.runId}</Go>
      </div>
      <Heading
        title={findingName(f)}
        sub={[engineNames[f.category], f.advisoryId ?? f.class ?? f.rule].filter(Boolean).join('  ·  ')}
        action={<Risk level={f.severity} />}
      />
      <div className="forensics detail-grid">
        <Panel title={t('find.tech')} action={<FileCode2 size={18} />}>
          <div className="panel-body">
            <div className="code-location">
              {f.path}
              {f.line && ':' + f.line}
            </div>
            {f.description && (
              <details className="evidence-list">
                <summary>{t('find.riskDesc')}</summary>
                <p>{f.description}</p>
              </details>
            )}
            {f.secretMasked && (
              <p>
                {t('find.valueInReport')} <code>{f.secretMasked}</code>
              </p>
            )}
            <EvidenceChain evidence={f.evidence} />
          </div>
        </Panel>
        <Panel title={t('find.recommendation')} action={<Shield size={18} />}>
          <div className="panel-body">
            {!!f.fixedVersions?.length && (
              <p>
                {t('find.fixedVersions')} <b>{f.fixedVersions?.join(', ')}</b>
              </p>
            )}
            <p>{f.remediation ?? t('find.noRecommendation')}</p>
            <button className="secondary" onClick={toggle}>
              <Check size={16} />
              {seen ? t('find.unmark') : t('find.mark')}
            </button>
            <small>{t('find.markNote')}</small>
            {error && <p role="alert">{error}</p>}
          </div>
        </Panel>
        {!USE_MOCKS && (f.category === 'SCA' || f.category === 'SECRET') && <PatchPanel run={run} f={f} />}
      </div>
      {f.ai && <Panel title={t('find.llm')}><div className="panel-body"><AiBlock ai={f.ai} /></div></Panel>}
    </>
  )
}
/** Готовый патч: просмотр без значения секрета и скачивание файла для `git apply`. */
function PatchPanel({ run, f }: { run: Run; f: Finding }) {
  const preview = useApi(() => api.getPatchPreview(run.runId, f.id), [run.runId, f.id])
  const file = 'fix-' + f.id.slice(-8) + '.patch'
  return (
    <Panel title={t('patch.title')} action={<Download size={18} />}>
      <div className="panel-body">
        {preview.state.status === 'loading' && <p>{t('patch.building')}</p>}
        {preview.state.status === 'error' && <p>{preview.state.error}</p>}
        {preview.state.status === 'ready' && (
          <>
            <pre className="evidence-list" style={{ overflowX: "auto" }} aria-label={t('patch.preview')}>{preview.state.data}</pre>
            <a className="secondary" href={api.patchUrl(run.runId, f.id)} download={file}>
              <Download size={16} />
              {t('patch.download')}
            </a>
            <small>
              {t('patch.runIn')} <code>git apply {file}</code>.
              {f.category === 'SECRET' && ' ' + t('patch.secretNote')}
            </small>
          </>
        )}
      </div>
    </Panel>
  )
}
export function Summary({ run, p }: { run: Run; p?: Project }) {
  const navigate = useNavigate()
  const [error, setError] = useState('')
  const rep = run.report
  async function markdown() {
    try {
      download(run.runId + '.md', await api.getReportMarkdown(run.runId), 'text/markdown')
    } catch (e) {
      setError(String(e))
    }
  }
  if (!rep)
    return (
      <p className="empty">
        {t('sum.unavailable')} <Go to={'/runs/' + run.runId}>{t('sum.openMonitor')}</Go>
      </p>
    )
  const quality = qualityFromValue(rep.quality)
  if (quality && Object.keys(rep.coverage.byAnalyzer).length === 0) {
    return (
      <>
        <Heading title={t('sum.qualityTitle')} sub={run.workflowName} action={<Go to={'/runs/' + run.runId}>{t('sum.stages')}</Go>} />
        <Panel title={t('sum.quality')}><div className="panel-body"><QualityResults quality={quality} /></div></Panel>
      </>
    )
  }
  return (
    <>
      <Heading
        title={t('sum.title')}
        sub={
          run.runId + ' · ' + niceDate(run.startedAt) + ' · ' + formatDuration(run.startedAt, run.finishedAt)
        }
        action={<><State value={run.status} />{p && <CompareLink run={run} runs={p.runs} />}</>}
      />
      <div className="report-distribution">
        <div>
          <h2>{t('sum.byRisk')}</h2>
          <p>
            {total(run.counts)} {t('sum.findingsDot')}{' '}
            {rep.coverage.status === 'COMPLETE' ? t('sum.fullCov') : t('sum.partCov')}
          </p>
        </div>
        <div className="risk-distribution-list">
          {SEVERITIES.map((s) => (
            <button key={s} onClick={() => navigate('/findings?run=' + run.runId + '&severity=' + s)}>
              <span>{severityNames[s]}</span>
              <span className="bar-track">
                <i
                  className={'bar-' + s}
                  style={{ width: (100 * run.counts[s]) / Math.max(1, total(run.counts)) + '%' }}
                />
              </span>
              <b>{run.counts[s]}</b>
            </button>
          ))}
        </div>
      </div>
      <div className="detail-grid">
        <Panel title={t('sum.priority')} action={<Go to={'/findings?run=' + run.runId}>{t('dash.allFindings')}</Go>}>
          <div className="records">
            {sorted(rep.findings)
              .slice(0, 4)
              .map((f) => (
                <Link key={f.id} to={findingUrl(run.runId, f)}>
                  <span className="record-title">
                    <b>{findingName(f)}</b>
                    <small className="report-remedy">{f.remediation}</small>
                  </span>
                  <Risk level={f.severity} />
                </Link>
              ))}
          </div>
        </Panel>
        <Trend runs={(p?.runs ?? []).filter((r) => r.startedAt <= run.startedAt)} />
      </div>
      <ReportDetails run={run} />
      {quality && <Panel title={t('sum.quality')}><div className="panel-body"><QualityResults quality={quality} /></div></Panel>}
      <Panel title={t('sum.export')}>
        <div className="panel-body">
          <p>
            {t('sum.covLine', { s: rep.coverage.status, v: rep.rulesVersion })}
          </p>
          <div className="inline-links">
            {USE_MOCKS ?
              <button className="secondary" onClick={() => download(run.runId + '.json', JSON.stringify(rep, null, 2), 'application/json')}>
                <FileJson size={16} />JSON
              </button> :
              <a className="secondary" href={api.reportJsonUrl(run.runId)} download><FileJson size={16} />JSON</a>
            }
            <button className="secondary" onClick={() => void markdown()}>
              <Download size={16} />
              Markdown
            </button>
            <button className="secondary" onClick={() => download(
              'report-' + run.runId.slice(0, 8) + '.html',
              reportHtml(rep, { workflowName: run.workflowName, finishedAt: run.finishedAt ?? undefined }),
              'text/html',
            )}>{t('sum.html')}</button>
            {!USE_MOCKS && <a className="secondary" href={api.reportPdfUrl(run.runId)} download><Download size={16} />PDF</a>}
            {!USE_MOCKS && <a className="secondary" href={api.reportSarifUrl(run.runId)} download><Download size={16} />SARIF</a>}
            {!USE_MOCKS && <a className="secondary" href={api.sbomUrl(run.runId)} download><Download size={16} />SBOM (CycloneDX)</a>}
            <Go to={'/runs/' + run.runId + '/details'}>{t('sum.fullTech')}</Go>
          </div>
          {error && <p role="alert">{error}</p>}
        </div>
      </Panel>
    </>
  )
}
/**
 * Детали проверки (запросы эксперта и экспертов): почему анализ неполный (файл и строка), AI-сводка,
 * проверенные безопасные места и секреты в тестах, какие правила применялись. Данные — отчёт сервера.
 */
function ReportDetails({ run }: { run: Run }) {
  const rep = run.report!
  const skipped = Object.entries(rep.coverage.byAnalyzer).flatMap(([id, c]) =>
    [...c.filesSkipped, ...c.unresolved].map((x) => `${id}: ${x.path}${x.line ? ':' + x.line : ''} — ${x.reason}`))
  const ai = runAi(run)
  return (
    <section className="stack report-details" aria-label={t('sum.detailsAria')}>
      <CoverageBanner
        status={rep.coverage.status}
        details={skipped.length > 0 && <ul className="coverage-list">{skipped.map((t, i) => <li key={i}>{t}</li>)}</ul>}
      />
      {ai && <AiSummary ai={ai} findings={runFindings(run)} />}
      <SafeSpots coverage={rep.coverage} />
      <ChecksApplied coverage={rep.coverage} />
    </section>
  )
}

export function Integrations({ workflowId }: { workflowId?: string }) {
  return (
    <>
      <Heading title={t('nav.integrations')} sub={t('int.sub')} />
      <div className="integration-registry">
        {[
          {
            name: 'GitHub Actions',
            icon: GitBranch,
            desc: t('int.gh'),
            note: t('int.fail'),
            to: '/ci?kind=github',
          },
          {
            name: 'GitLab CI',
            icon: Network,
            desc: t('int.gl'),
            note: t('int.fail'),
            to: '/ci?kind=gitlab',
          },
          {
            name: 'Telegram',
            icon: Send,
            desc: t('tg.defaultsHint'),
            note: t('int.secrets'),
            to: '/settings#telegram',
          },
          {
            name: t('tg.otherNotifications'),
            icon: BookOpen,
            desc: t('int.notify'),
            note: t('int.secrets'),
            to: '/editor',
          },
        ].map((x) => (
          <section className="integration-row" key={x.name}>
            <span className="integration-symbol">
              {x.name === 'GitHub Actions' ? (
                <img src={githubMark} width="21" height="21" alt="" />
              ) : (
                <x.icon />
              )}
            </span>
            <div>
              <h2>{x.name}</h2>
              <p>{x.desc}</p>
            </div>
            <small>
              {USE_MOCKS ? t('int.demo') : x.note}
            </small>
            <Link className="quiet-action" to={x.to + (workflowId && x.to.startsWith('/ci') ? '&workflowId=' + encodeURIComponent(workflowId) : '')}>
              {x.to.startsWith('/ci') ? t('int.yaml') : x.to.startsWith('/settings') ? t('tg.configure') : t('int.openWf')}
            </Link>
          </section>
        ))}
      </div>
    </>
  )
}
