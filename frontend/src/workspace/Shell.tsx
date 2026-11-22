import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, Navigate, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  Bell,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  FileBarChart2,
  Folder,
  FolderKanban,
  FolderPlus,
  GitFork,
  Home,
  Layers3,
  Menu,
  Network,
  Play,
  Search,
  Settings,
  ShieldCheck,
  X,
} from 'lucide-react'
import logo from '../ui/logo.svg'
import { api, USE_MOCKS, errorMessage } from '../api/client'
import { useLiveRun } from '../store'
import { type NodeDefinition, type Run } from '../api/types'
import { featureItems, nodeItems, search, type SearchItem } from './searchIndex'
import { Loading, ErrorBox } from '../ui'
import { Dashboard } from './Dashboard'
import { Compare } from './Compare'
import { FindingPage, Findings, History, Integrations, Library, LoadedRun, Projects, RoutesForProject, Summary } from './Pages'
import { findingName, findingUrl, lastReport, lastUploadId, loadProjects, sorted, type Project } from './data'
import { Heading } from './parts'
import { LANGS, locale, setLang, t, useLang } from '../i18n'
import { BRAND } from '../brand'
import { useDemo } from '../api/demo'
const topNav = [
  { label: 'nav.overview', path: '/', icon: Home },
  { label: 'nav.projects', path: '/projects', icon: FolderKanban },
  { label: 'nav.routes', path: '/routes', icon: GitFork },
  { label: 'nav.builder', path: '/editor', icon: Layers3 },
  { label: 'nav.runs', path: '/history', icon: Play },
  { label: 'nav.findings', path: '/findings', icon: ShieldCheck },
  { label: 'nav.reports', path: '/reports', icon: FileBarChart2 },
]
const bottomNav = [
  { label: 'nav.integrations', path: '/integrations', icon: Network },
  { label: 'nav.settings', path: '/settings', icon: Settings },
]
type Overlay = 'search' | 'alerts' | 'profile' | 'help' | null
function ReportRoute({ p }: { p?: Project }) {
  const { runId = '' } = useParams()
  return <LoadedRun id={runId}>{(run) => <Summary run={run} p={p} />}</LoadedRun>
}
function loadSelected() {
  try {
    return localStorage.getItem('workspace.project') ?? ''
  } catch {
    return ''
  }
}
export function Shell({ legacy }: { legacy: ReactNode }) {
  const nav = useNavigate(),
    loc = useLocation(),
    [mobile, setMobile] = useState(false),
    [overlay, setOverlay] = useState<Overlay>(null),
    [query, setQuery] = useState(''),
    [active, setActive] = useState(0),
    [nodeDefs, setNodeDefs] = useState<NodeDefinition[]>([])
  const [projects, setProjects] = useState<Project[]>([]),
    [ready, setReady] = useState(false),
    [problem, setProblem] = useState(''),
    [attempt, retry] = useState(0)
  const [selected, setSelected] = useState(loadSelected),
    [run, setRun] = useState<Run>(),
    [busy, setBusy] = useState(false),
    [alert, setAlert] = useState('')
  const dialog = useRef<HTMLDialogElement>(null),
    prevFocus = useRef<HTMLElement | null>(null),
    searchInput = useRef<HTMLInputElement>(null),
    menuButton = useRef<HTMLButtonElement>(null)
  const live = useLiveRun((s) => s.status)
  const lang = useLang()
  const demo = useDemo()
  useEffect(() => {
    let ok = true
    loadProjects()
      .then((v) => {
        if (ok) {
          setProjects(v)
          setReady(true)
          setProblem('')
        }
      })
      .catch((e) => {
        if (ok) {
          setReady(true)
          setProblem(errorMessage(e))
        }
      })
    return () => {
      ok = false
    }
  }, [loc.pathname, live, attempt])
  const [, segment, resource] = loc.pathname.split('/')
  const linkedProject = projects.find(item => (
    ((segment === 'runs' || segment === 'findings') && item.runs.some(r => r.runId === resource)) ||
    (segment === 'workflows' && item.flows.some(w => w.id === resource))
  ))
  useEffect(()=>{
    if(linkedProject && linkedProject.id !== selected) {
      setSelected(linkedProject.id)
      try { localStorage.setItem('workspace.project',linkedProject.id) } catch { /* Session-only context. */ }
    }
  },[linkedProject,selected])
  const p = linkedProject ?? projects.find((item) => item.id === selected) ?? projects[0]
  const latestRunId = p?.runs[0]?.runId
  useEffect(() => {
    let valid = true
    setRun(undefined)
    if (latestRunId)
      api
        .getRun(latestRunId)
        .then((r) => {
          if (valid) setRun(r)
        })
        .catch((e) => {
          if (valid) setAlert(errorMessage(e))
        })
    return () => {
      valid = false
    }
  }, [latestRunId, attempt])
  const close = useCallback(() => {
    setOverlay(null)
    setQuery('')
    setActive(0)
  }, [])
  useEffect(() => {
    if (overlay !== 'search' || nodeDefs.length) return
    api.listNodes().then(setNodeDefs).catch(() => { /* Без каталога нод поиск работает по функциям и данным. */ })
  }, [overlay, nodeDefs.length])
  useEffect(() => {
    close()
    setMobile(false)
    setAlert('')
    window.scrollTo(0, 0)
  }, [loc.pathname, loc.search, close])
  useEffect(() => {
    function key(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOverlay((v) => (v === 'search' ? null : 'search'))
      }
      if (e.key === 'Escape' && mobile) {
        setMobile(false)
        menuButton.current?.focus()
      }
    }
    document.addEventListener('keydown', key)
    return () => document.removeEventListener('keydown', key)
  }, [mobile])
  useEffect(() => {
    const d = dialog.current
    if (!d) return
    if (overlay && !d.open) {
      prevFocus.current = document.activeElement as HTMLElement
      d.showModal()
    }
    // showModal отдаёт фокус первой кнопке (закрыть) — в поиске печатать нужно сразу.
    if (overlay === 'search') searchInput.current?.focus()
    if (!overlay && d.open) {
      d.close()
      prevFocus.current?.focus()
    }
  }, [overlay])
  function choose(item: Project) {
    setProjects(items => items.some(p => p.id === item.id) ? items : [...items, item])
    setSelected(item.id)
    try {
      localStorage.setItem('workspace.project', item.id)
    } catch {
      /* Session selection remains available. */
    }
    close()
    nav('/', {replace:loc.search === '?new=1'})
  }
  async function launch() {
    const workflow = p?.flows.find(w => w.nodes.some(n => n.type === 'trigger.manual'))
    if (!workflow || busy) return
    setBusy(true)
    setAlert('')
    try {
      if (p?.kind === 'archive') {
        const uploadId = lastUploadId(p)
        if (!uploadId) throw new Error(t('zip.noUpload'))
        nav('/runs/' + (await api.runWorkflow(workflow.id, { source: { kind: 'upload', uploadId } })).runId)
        return
      }
      const r = await api.runWorkflow(workflow.id)
      nav('/runs/' + r.runId)
    } catch (e) {
      setAlert(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  async function createFromTemplate() {
    if (!p || busy) return
    setBusy(true)
    setAlert('')
    try {
      await api.copyTemplate('release', { repoUrl: p.repo })
      retry((n) => n + 1)
    } catch (e) {
      setAlert(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const section = loc.pathname.startsWith('/workflows/')
    ? '/editor'
    : loc.pathname.startsWith('/runs/')
      ? loc.pathname.endsWith('/report') || loc.pathname.endsWith('/details')
        ? '/reports'
        : '/history'
      : ['/templates', '/scenarios', '/workflows'].includes(loc.pathname)
        ? '/editor'
        : loc.pathname === '/ci'
          ? '/integrations'
          : '/' + (loc.pathname.split('/')[1] ?? '')
  const current = [...topNav, ...bottomNav].find((n) => n.path === section)
  const editorPath = p?.flows[0] ? '/workflows/' + p.flows[0].id : '/workflows/new'
  const searchItems: SearchItem[] = [
    ...featureItems({ latestRunId, firstWorkflowId: p?.flows[0]?.id }),
    ...nodeItems(nodeDefs, editorPath),
    ...projects.map((pr): SearchItem => ({ name: pr.name, kind: 'project', path: '/', hint: pr.kind === 'archive' ? t('proj.kindZip') : pr.repo, projectId: pr.id })),
    ...(p?.flows ?? []).map((w): SearchItem => ({ name: w.name, kind: 'workflow', path: '/workflows/' + w.id, hint: t('search.openInBuilder') })),
    ...(run?.report?.findings ?? []).map((f): SearchItem => ({
      name: findingName(f), kind: 'finding', path: findingUrl(run!.runId, f), hint: f.path + (f.line ? ':' + f.line : ''), keywords: f.category + ' ' + f.severity,
    })),
    ...(p?.runs ?? []).map((r): SearchItem => ({
      name: (r.workflowName ?? t('kind.run')) + ' · ' + new Date(r.startedAt).toLocaleString(locale(), { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }),
      kind: 'run', path: '/runs/' + r.runId, keywords: r.runId,
    })),
  ]
  const SUGGESTED = ['builder', 'ai', 'run', 'download', 'templates', 'llm']
  const searchResults = query.trim()
    ? search(searchItems, query)
    : SUGGESTED.map((id) => searchItems.find((i) => i.id === id)).filter((i): i is SearchItem => Boolean(i))
  function openResult(r: SearchItem) {
    const project = r.projectId ? projects.find((item) => item.id === r.projectId) : undefined
    if (project) choose(project)
    else {
      close()
      nav(r.path)
    }
  }
  function navItem(n: (typeof topNav)[number]) {
    return (
      <Link
        key={n.path}
        aria-label={t(n.label)}
        aria-current={section === n.path ? 'page' : undefined}
        className={'nav-item ' + (section === n.path ? 'selected' : '')}
        onClick={() => setMobile(false)}
        to={n.path}
      >
        <n.icon size={19} />
        <span>{t(n.label)}</span>
      </Link>
    )
  }
  return (
    <div className="workspace">
      <header className="topbar">
        <button
          ref={menuButton}
          aria-label={t('shell.menu')}
          aria-expanded={mobile}
          aria-controls="app-rail"
          className="icon-btn mobile-menu"
          onClick={() => setMobile(!mobile)}
        >
          <Menu />
        </button>
        <Link className="brand" to="/">
          <img src={logo} alt={t('shell.bank')} />
        </Link>
        <span className="product">{BRAND}</span>
        <button
          aria-label={t('shell.search')}
          className="search-trigger"
          onClick={() => setOverlay('search')}
        >
          <Search size={17} />
          <span>{t('shell.search')}</span>
          <kbd>Ctrl K</kbd>
        </button>
        <div className="top-actions">
          <div className="lang-switch" role="group" aria-label={t('lang.label')}>
            {LANGS.map((l) => (
              <button
                key={l}
                type="button"
                className={lang === l ? 'on' : undefined}
                aria-pressed={lang === l}
                aria-label={t('lang.' + l)}
                lang={l}
                onClick={() => setLang(l)}
              >
                {l.toUpperCase()}
              </button>
            ))}
          </div>
          <button className="icon-btn" aria-label={t('shell.alerts')} onClick={() => setOverlay('alerts')}>
            <Bell size={19} />
            {run?.counts.CRITICAL ? <i /> : null}
          </button>
          <button
            className="icon-btn help-btn"
            aria-label={t('shell.guide')}
            onClick={() => setOverlay('help')}
          >
            <CircleHelp size={18} />
          </button>
          <button
            className="profile"
            aria-label={t('shell.profile')}
            onClick={() => setOverlay('profile')}
          >
            <span>SE</span>
            <ChevronDown size={13} />
          </button>
        </div>
      </header>
      {demo && <div className="demo-banner" role="status">{t('demo.banner')}</div>}
      {mobile && <button aria-label={t('shell.closeMenu')} className="scrim" onClick={() => setMobile(false)} />}
      <aside id="app-rail" className={'rail ' + (mobile ? 'open' : '')}>
        <nav aria-label={t('nav.groupProject')}>{topNav.slice(0,2).map(navItem)}</nav>
        <nav aria-label={t('nav.groupChecks')}>{topNav.slice(2).map(navItem)}</nav>
        <div className="rail-bottom">
          <nav>{bottomNav.map(navItem)}</nav>
          <div className="mode">
            <span className="led" />
            {USE_MOCKS ? t('shell.demoMode') : t('shell.serverMode')}
          </div>
        </div>
      </aside>
      <main className="workspace-main">
        <div className="crumb">
          {USE_MOCKS && <span className="mobile-mode">{t('shell.demoShort')}</span>}
          <Folder size={14} />
          <Link to="/projects">{t('nav.projects')}</Link>
          {loc.pathname !== '/projects' && <ChevronRight size={13} />}
          {loc.pathname === '/projects' ? null : <Link to="/">{p?.name ?? t('shell.desk')}</Link>}
          {loc.pathname === '/' && <Link className="crumb-add" to="/projects?new=1"><FolderPlus size={15}/>{t('proj.add')}</Link>}
          {section !== '/' && section !== '/projects' && current && (
            <>
              <ChevronRight size={13} />
              <span>{t(current.label)}</span>
            </>
          )}
        </div>
        {alert && <ErrorBox error={alert} onRetry={() => retry((v) => v + 1)} />}
        {!ready ? (
          <div className="skeleton">
            <Loading text={t('shell.loadingWs')} />
          </div>
        ) : problem ? (
          <ErrorBox error={problem} onRetry={() => retry((v) => v + 1)} />
        ) : (
          <Routes>
            <Route path="/projects" element={<Projects projects={projects} choose={choose} />} />
            <Route path="/integrations" element={<Integrations workflowId={p?.flows[0]?.id} />} />
            {p && (
              <>
                <Route
                  path="/"
                  element={
                    latestRunId && !run && !alert ? (
                      <div className="skeleton">
                        <Loading />
                      </div>
                    ) : (
                      <Dashboard project={p} run={run?.runId === latestRunId ? run : undefined} launch={() => void launch()} busy={busy} onCreate={() => void createFromTemplate()} />
                    )
                  }
                />
                <Route path="/routes" element={<RoutesForProject key={p.id} project={p} />} />
                <Route path="/scenarios" element={<Library p={p} />} />
                <Route path="/editor" element={<Navigate replace to={p.flows[0] ? '/workflows/' + p.flows[0].id : '/workflows/new'} />} />
                <Route path="/history" element={new URLSearchParams(loc.search).has('workflowId') ? legacy : <History p={p} />} />
                <Route path="/reports" element={<History p={p} reports />} />
                <Route path="/findings" element={<Findings defaultRun={latestRunId} lastReportRun={p ? lastReport(p)?.runId : undefined} />} />
              </>
            )}
            {!p && <Route path="/history" element={legacy} />}
            {!p &&
              ['/', '/routes', '/scenarios', '/editor', '/reports', '/findings'].map((path) => (
                <Route
                  key={path}
                  path={path}
                  element={
                    <Heading
                      title={t('shell.noProjects')}
                      sub={t('shell.noProjectsSub')}
                      action={
                        <Link className="secondary" to="/projects?new=1">
                          {t('proj.add')}
                        </Link>
                      }
                    />
                  }
                />
              ))}
            <Route path="/runs/:runId/report" element={<ReportRoute p={p} />} />
            <Route path="/compare" element={<Compare />} />
            <Route path="/findings/:runId/:findingId" element={<FindingPage />} />
            <Route path="*" element={legacy} />
          </Routes>
        )}
      </main>
      <dialog
        ref={dialog}
        className="overlay"
        onCancel={close}
        onClick={(e) => {
          if (e.target === e.currentTarget) close()
        }}
      >
        <div>
          <div className="dialog-head">
            <h2>
              {overlay === 'search'
                ? t('shell.searchTitle')
                : overlay === 'alerts'
                  ? t('shell.alerts')
                  : overlay === 'help'
                    ? t('shell.guideTitle')
                    : t('shell.profileTitle')}
            </h2>
            <button className="icon-btn" onClick={close} aria-label={t('ui.close')}>
              <X size={18} />
            </button>
          </div>
          {overlay === 'search' && (
            <>
              <label className="filter-input">
                <Search size={17} />
                <input
                  ref={searchInput}
                  aria-label={t('shell.whatFind')}
                  aria-controls="search-results"
                  aria-activedescendant={searchResults[active] ? 'search-result-' + active : undefined}
                  placeholder={t('shell.searchPh')}
                  value={query}
                  onChange={(e) => {
                    setQuery(e.target.value)
                    setActive(0)
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'ArrowDown') {
                      e.preventDefault()
                      setActive((v) => Math.min(v + 1, searchResults.length - 1))
                    } else if (e.key === 'ArrowUp') {
                      e.preventDefault()
                      setActive((v) => Math.max(v - 1, 0))
                    } else if (e.key === 'Enter' && searchResults[active]) {
                      e.preventDefault()
                      openResult(searchResults[active])
                    }
                  }}
                />
              </label>
              {!query.trim() && <p className="search-caption">{t('shell.often')}</p>}
              <div className="search-list" id="search-results" role="listbox" aria-label={t('shell.results')}>
                {searchResults.map((r, i) => (
                  <button
                    key={r.kind + r.path + r.name}
                    id={'search-result-' + i}
                    role="option"
                    aria-selected={i === active}
                    className={i === active ? 'active' : undefined}
                    onMouseEnter={() => setActive(i)}
                    onClick={() => openResult(r)}
                  >
                    <span className="search-text">
                      <b>{r.name}</b>
                      {r.hint && <small>{r.hint}</small>}
                    </span>
                    <span className="search-kind">{t('kind.' + r.kind)}</span>
                  </button>
                ))}
                {!searchResults.length && <p>{t('shell.noResults')}</p>}
              </div>
            </>
          )}
          {overlay === 'alerts' && (
            <div className="search-list">
              {sorted(run?.report?.findings ?? [])
                .filter((f) => f.severity === 'CRITICAL')
                .map((f) => (
                  <Link key={f.id} to={findingUrl(run!.runId, f)} onClick={close}>
                    <b>{findingName(f)}</b>
                    <small>{t('shell.critFinding')} · {run?.runId}</small>
                  </Link>
                ))}
              {!run?.counts.CRITICAL && <p>{t('shell.noCrit')}</p>}
            </div>
          )}
          {overlay === 'help' && (
            <>
              <p>
                {t('shell.help1')}
              </p>
              <p>
                {t('shell.help2')}
              </p>
              <Link className="secondary" to="/scenarios" onClick={close}>
                {t('shell.openRoutes')}
              </Link>
            </>
          )}
          {overlay === 'profile' && (
            <>
              <p>
                <b>Security Engineering</b>
              </p>
              <p>
                {USE_MOCKS
                  ? t('shell.profileDemo')
                  : t('shell.profileReal')}
              </p>
              <Link to="/settings" className="secondary" onClick={close}>
                {t('nav.settings')}
              </Link>
            </>
          )}
        </div>
      </dialog>
    </div>
  )
}
