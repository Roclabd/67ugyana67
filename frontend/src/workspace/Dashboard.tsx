import { useId, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  CircleHelp,
  Clock3,
  FileCheck2,
  FileArchive,
  FolderGit2,
  GitBranch,
  GitPullRequest,
  Layers3,
  ListChecks,
  Play,
  Radar,
  ShieldCheck,
  Workflow as FlowIcon,
} from 'lucide-react'
import type { Report, Run, RunSummary, Workflow } from '../api/types'
import { formatDuration } from '../ui/format'
import { Engine, Go, Panel, Risk, State } from './parts'
import { engines, engineNames, findingName, findingUrl, niceDate, score, sorted, type Project } from './data'
import github from '../ui/github.svg'
import { t } from '../i18n'
import { ZipCheckButton } from './ZipCheck'

function Gauge({ run }: { run: Run }) {
  const [explain, setExplain] = useState(false)
  const complete = run.coverageStatus === 'COMPLETE'
  const value = complete ? score(run.counts) : null
  const point = (i: number, r: number) => [
    110 + r * Math.cos(Math.PI + (i * Math.PI) / 100),
    107 + r * Math.sin(Math.PI + (i * Math.PI) / 100),
  ]
  const arc = (i: number, j: number, r: number) =>
    'M ' + point(i, r).join(' ') + ' A ' + r + ' ' + r + ' 0 0 1 ' + point(j, r).join(' ')
  return (
    <Panel
      className="score-panel"
      title={t('dash.secLevel')}
      action={
        <button
          className="icon-btn small"
          aria-label={t('dash.formulaAria')}
          aria-expanded={explain}
          onClick={() => setExplain(!explain)}
        >
          <CircleHelp size={16} />
        </button>
      }
    >
      {explain ? (
        <p className="formula">
          {t('dash.formula')}
        </p>
      ) : (
        <div className="gauge">
          <svg viewBox="0 0 220 122" aria-hidden="true">
            <path d={arc(0, 100, 88)} stroke="#233e51" strokeWidth="15" fill="none" strokeLinecap="round" />
            {value !== null && (
              <path
                d={arc(0, Math.max(0.01, value), 88)}
                stroke="#70cc86"
                strokeWidth="15"
                fill="none"
                strokeLinecap="round"
              />
            )}
            {Array.from({ length: 31 }, (_, i) => (
              <path
                key={i}
                d={
                  'M ' +
                  point((i * 100) / 30, 67).join(' ') +
                  ' L ' +
                  point((i * 100) / 30, i % 5 === 0 ? 74 : 71).join(' ')
                }
                stroke="#527082"
              />
            ))}
          </svg>
          <strong>
            {value ?? '—'}
            <small>/100</small>
          </strong>
        </div>
      )}
      {!explain && complete && <p className="index-formula">{t('dash.indexFormula')}</p>}
      <div className="gauge-caption">
        <span className="led amber" />
        {complete ? t('dash.basedOn') : t('dash.lowCoverage')}
      </div>
    </Panel>
  )
}
function Diagram({ flow }: { flow: Workflow }) {
  const nodeTypes = new Set(flow.nodes.map(node => node.type))
  const available = engines.filter(engine => nodeTypes.has(engine.type))
  return (
    <div className="mini-flow run-components" aria-label={t('dash.diagAria')}>
      {nodeTypes.has('source.repo') && <span><FolderGit2 size={17} />{t('dash.gitRepo')}</span>}
      {nodeTypes.has('source.archive') && <span><FolderGit2 size={17} />{t('dash.zip')}</span>}
      {available.map(engine => <span key={engine.key}><Engine id={engine.key} />{engineNames[engine.key]}</span>)}
      {nodeTypes.has('output.report') && <span><FileCheck2 size={17} />{t('dash.report')}</span>}
      {nodeTypes.has('output.route-map') && <span><Layers3 size={17} />{t('dash.routeMap')}</span>}
    </div>
  )
}
export function Trend({ runs }: { runs: RunSummary[] }) {
  const [period, setPeriod] = useState(7)
  const id = useId().replace(/:/g, '')
  const good = runs.filter((r) => r.coverageStatus === 'COMPLETE')
  const end = good.length ? Date.parse(good[0].startedAt) : 0
  const items = good.filter((r) => end - Date.parse(r.startedAt) < period * 86400000).reverse()
  const min = Math.max(0, Math.floor(Math.min(...items.map((r) => score(r.counts)), 80) / 10) * 10 - 10)
  const max = Math.min(100, Math.ceil(Math.max(...items.map((r) => score(r.counts)), 50) / 10) * 10 + 10)
  const firstTime = items.length ? Date.parse(items[0].startedAt) : end
  const points = items.map((r) => ({
    x: 34 + (end === firstTime ? 0.5 : (Date.parse(r.startedAt) - firstTime) / (end - firstTime)) * 374,
    y: 84 - (70 * (score(r.counts) - min)) / (max - min),
    r,
  }))
  const line = points.map((p) => p.x + ',' + p.y).join(' ')
  return (
    <Panel
      className="trend-panel"
      title={t('dash.trend')}
      action={
        <select
          aria-label={t('dash.period')}
          value={period}
          onChange={(e) => setPeriod(Number(e.target.value))}
        >
          <option value="7">{t('dash.7d')}</option>
          <option value="30">{t('dash.30d')}</option>
        </select>
      }
    >
      {points.length ? (
        <>
          <div className="chart-key">
            <i /> {t('dash.secIndex')}
          </div>
          <svg
            className="trend"
            viewBox="0 0 422 96"
            preserveAspectRatio="none"
            role="img"
            aria-label={t('dash.indexByRuns') + items.map((r) => score(r.counts)).join(', ')}
          >
            <defs>
              <linearGradient id={id} x2="0" y2="1">
                <stop stopColor="#68c783" stopOpacity=".3" />
                <stop offset="1" stopColor="#68c783" stopOpacity="0" />
              </linearGradient>
            </defs>
            {[12, 37, 62, 87].map((y) => (
              <line key={y} x1="29" x2="422" y1={y} y2={y} stroke="#2a4050" strokeDasharray="3 5" />
            ))}
            <text x="0" y="16" fill="#a9bbc9" fontSize="11">
              {max}
            </text>
            <text x="0" y="88" fill="#a9bbc9" fontSize="11">
              {min}
            </text>
            <polygon
              points={points[0].x + ',94 ' + line + ' ' + points[points.length - 1].x + ',94'}
              fill={'url(#' + id + ')'}
            />
            <polyline points={line} fill="none" stroke="#77cf8b" strokeWidth="2.7" />
            {points.map((p) => (
              <circle key={p.r.runId} cx={p.x} cy={p.y} r="3.6" fill="#8cdd9c">
                <title>
                  {niceDate(p.r.startedAt)} · {score(p.r.counts)} {t('dash.points')}
                </title>
              </circle>
            ))}
          </svg>
          <div className="chart-axis">
            <span>{niceDate(items[0].startedAt, false)}</span>
            <span>{niceDate(items[items.length - 1].startedAt, false)}</span>
          </div>
        </>
      ) : (
        <p className="empty">{t('dash.noFull')}</p>
      )}
      <details className="score-notes"><summary>{t('dash.howIndex')}</summary><p>{t('dash.howIndexText')}</p></details>
    </Panel>
  )
}
export function Timeline({ runs }: { runs: RunSummary[] }) {
  return (
    <div className="timeline">
      {runs.slice(0, 4).map((r) => (
        <Link key={r.runId} to={'/runs/' + r.runId}>
          <i className={'led ' + (r.status === 'SUCCESS' ? '' : r.status === 'FAILED' ? 'red' : 'amber')} />
          <span>
            <b>{r.workflowName || r.workflowId}</b>
            <small>{r.runId} · {niceDate(r.startedAt)}</small>
          </span>
          <State value={r.status} />
        </Link>
      ))}
    </div>
  )
}
export function Dashboard({
  project: p,
  run,
  launch,
  busy,
  onCreate,
}: {
  project: Project
  run?: Run
  launch: () => void
  busy: boolean
  onCreate?: () => void
}) {
  const flow = p.flows[0]
  const report: Report | null = run?.report ?? null
  const findings = sorted(report?.findings ?? [])
  const critical = findings.filter((f) => f.severity === 'CRITICAL').length
  const active = p.runs.filter((r) => r.status === 'RUNNING').length
  const current = p.runs[0]
  const wf = p.flows.find((w) => w.id === current?.workflowId) ?? flow
  const coverage = Object.values(report?.coverage.byAnalyzer ?? {})
  const currentUrl = current ? '/runs/' + current.runId : '/history'
  const stats = [
    {
      label: t('dash.activeChecks'),
      value: active,
      icon: Activity,
      theme: 'blue',
      hint: active ? t('dash.runningNow') : t('dash.queueFree'),
      to: '/history',
    },
    {
      label: t('dash.critical'),
      value: report ? critical : '—',
      icon: AlertTriangle,
      theme: 'red',
      hint: !report ? t('dash.noChecksYet') : critical ? t('dash.needAttention') : t('dash.inSelected'),
      to: '/findings?severity=CRITICAL',
    },
    {
      label: t('dash.totalFindings'),
      value: report ? findings.length : '—',
      icon: ShieldCheck,
      theme: 'cyan',
      hint: report ? t('dash.inLatest') : t('dash.noChecksYet'),
      to: '/findings',
    },
    {
      label: t('dash.analyzerCoverage'),
      value: coverage.length
        ? Math.round((100 * coverage.filter((c) => c.status === 'COMPLETE').length) / coverage.length) + '%'
        : '—',
      icon: Layers3,
      theme: 'green',
      hint: !coverage.length ? t('dash.awaitCheck') : t('dash.covDone', { a: coverage.filter((c) => c.status === 'COMPLETE').length, b: coverage.length }),
      to: '/reports',
    },
  ]
  return (
    <div className="dash">
      <div className="project-hero">
        <div className="project-icon">
          {p.kind === 'archive' ? <FileArchive size={32} strokeWidth={1.5} /> : <FolderGit2 size={32} strokeWidth={1.5} />}
        </div>
        <div className="project-label">
          <h1>{p.name}</h1>
          <p className="project-desc">{t('dash.heroDesc')}</p>
          <div className="meta-line">
            <span>
              {p.kind === 'archive' ? <FileArchive size={14} /> : p.repo.includes('github.com') && <img src={github} alt="" />}{' '}
              {p.kind === 'archive' ? t('zip.kind') : p.repo.includes('github.com') ? 'GitHub' : 'GitLab'}
            </span>
            <em />
            {p.kind === 'archive' ? <span>{t('zip.metaNote')}</span> : (
              <>
                <span>
                  <GitBranch size={14} /> {p.branch}
                </span>
                <em />
                <span>{p.repo}</span>
              </>
            )}
          </div>
        </div>
        {p.flows.length === 0 && onCreate ? (
          <button className="primary" disabled={busy} onClick={onCreate}>
            <Play size={16} fill="currentColor" />
            {busy ? t('dash.creating') : t('dash.createFromTpl')}
          </button>
        ) : (
          <button className="primary" disabled={busy || !p.flows.some(w => w.nodes.some(n => n.type === 'trigger.manual'))} onClick={launch}>
            <Play size={16} fill="currentColor" />
            {busy ? t('dash.starting') : t('dash.runCheck')}
          </button>
        )}
        <ZipCheckButton project={p} />
      </div>
      <div className="kpis">
        {stats.map((s) => (
          <Link key={s.label} className={'kpi ' + s.theme} to={s.to}>
            <div className="kpi-top">
              <span className="kpi-icon">
                <s.icon size={19} />
              </span>
              <span>{s.label}</span>
            </div>
            <strong>{s.value}</strong>
            <small>{s.hint}</small>
          </Link>
        ))}
      </div>
      <div className="board-row">
        <Panel
          className="workflow-panel"
          title={t('dash.curWorkflow')}
          action={<Go to={wf ? '/workflows/' + wf.id : '/workflows/new'}>{wf ? t('nav.builder') : t('dash.createWorkflow')}</Go>}
        >
          {wf ? <>
          <div className="wf-title">
            <span className="wf-icon">
              <FlowIcon size={17} />
            </span>
            <b>{wf.name}</b>
            {current && <State value={current.status} />}
          </div>
          <Diagram flow={wf} />
          <div className="wf-foot">
            <span>
              <GitPullRequest size={14} />
              {wf.nodes.length} {t('dash.stages')}
            </span>
            <span>
              <Clock3 size={14} />
              {current ? formatDuration(current.startedAt, current.finishedAt) : '—'}
            </span>
            <Go to={currentUrl}>{t('dash.runLog')}</Go>
          </div>
          </> : <p className="empty">{t('dash.noWorkflow')}</p>}
        </Panel>
        {report && run ? (
          <Gauge run={run} />
        ) : (
          <Panel title={t('dash.secLevel')}>
            <p className="empty">{current ? t('dash.noReportYet') : t('dash.awaitFirst')}</p>
          </Panel>
        )}
      </div>
      <div className="board-row">
        <Panel title={t('dash.latestFindings')} action={<Go to="/findings">{t('dash.allFindings')}</Go>}>
          <div className="compact-table">
            <table>
              <thead>
                <tr>
                  <th>{t('dash.thSeverity')}</th>
                  <th>{t('dash.thFinding')}</th>
                  <th>{t('dash.thAnalyzer')}</th>
                </tr>
              </thead>
              <tbody>
                {findings.slice(0, 4).map((f) => (
                  <tr key={f.id}>
                    <td>
                      <Risk level={f.severity} />
                    </td>
                    <td>
                      <Link to={findingUrl(run!.runId, f)}>{findingName(f)}</Link>
                      <small>
                        {f.path.split('/').pop()}
                        {f.line ? ':' + f.line : ''}
                      </small>
                    </td>
                    <td>
                      <span className="engine-tag">{engineNames[f.category]}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!findings.length && <p className="empty">{!report ? t('dash.reportUnavailable') : report.coverage.status === 'COMPLETE' ? t('dash.noFindings') : t('dash.noFindingsPartial')}</p>}
          </div>
        </Panel>
        <Trend runs={p.runs} />
      </div>
      <div className="board-row">
        <Panel title={t('dash.runHistory')} action={<Go to="/history">{t('dash.allRuns')}</Go>}>
          <Timeline runs={p.runs} />
        </Panel>
        <Panel title={t('dash.analyzers')} action={<Radar size={17} />}>
          <div className="engine-list">
            {engines.map((e) => {
              const id = p.flows.find(flow => flow.id === run?.workflowId)?.nodes.find(n => n.type === e.type)?.id
              return (
                <div key={e.key}>
                  <span className="engine-icon">
                    <Engine id={e.key} />
                  </span>
                  <span>
                    <b>{engineNames[e.key]}</b>
                    <small>{e.name}</small>
                  </span>
                  <span className="engine-count">
                    {id && report?.coverage.byAnalyzer[id]?.status === 'COMPLETE' ? t('dash.ready') : '—'}
                  </span>
                </div>
              )
            })}
          </div>
        </Panel>
      </div>
      <div className="board-row">
        <Panel title={t('nav.integrations')} action={<Go to="/integrations">{t('dash.configure')}</Go>}>
          <div className="single-line">
            <GitBranch size={19} /> {t('dash.ghAndGl')} <small>{t('dash.ciConfigs')}</small>
          </div>
        </Panel>
        <Panel title={t('dash.activity')}>
          <div className="single-line">
            <ListChecks size={19} />
            {report ? t('dash.reportBuilt') : current ? t('dash.runNoReport') : t('dash.noRuns')}{' '}
            {report && run && <Go to={'/runs/' + run.runId + '/report'}>{run.runId}</Go>}
          </div>
        </Panel>
      </div>
    </div>
  )
}
