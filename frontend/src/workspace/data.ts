import { api, USE_MOCKS } from '../api/client'
import { SEVERITIES, type Finding, type RunSummary, type SeverityCounts, type Workflow } from '../api/types'
import { t, locale } from '../i18n'

export const severityNames = {
  get CRITICAL() { return t('sevf.CRITICAL') },
  get HIGH() { return t('sevf.HIGH') },
  get MEDIUM() { return t('sevf.MEDIUM') },
  get LOW() { return t('sevf.LOW') },
}
export const engineNames = { SECRET: 'Secrets', SCA: 'SCA', SAST: 'SAST' }
export const engines = [
  { key: 'SAST', get name() { return t('engine.sast') }, type: 'analyzer.sast' },
  { key: 'SCA', get name() { return t('engine.sca') }, type: 'analyzer.sca' },
  { key: 'SECRET', get name() { return t('engine.secret') }, type: 'analyzer.secret' },
] as const
export const niceDate = (date: string, time = true) =>
  new Date(date).toLocaleString(locale(), {
    day: '2-digit',
    month: 'short',
    ...(time ? ({ hour: '2-digit', minute: '2-digit' } as const) : {}),
  })
export const total = (c: SeverityCounts) => Object.values(c).reduce((a, b) => a + b, 0)
export const score = (c: SeverityCounts) =>
  Math.max(0, 100 - c.CRITICAL * 8 - c.HIGH * 2 - c.MEDIUM - Math.ceil(c.LOW / 2))
export const sorted = (f: Finding[]) =>
  [...f].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
export const findingName = (f: Finding) => (f.artifact ? f.artifact + ' ' + f.version : (f.title ?? f.rule))
export const findingUrl = (run: string, f: Finding) =>
  '/findings/' + encodeURIComponent(run) + '/' + encodeURIComponent(f.id)
export interface Project {
  id: string
  name: string
  /** repo - проект по ссылке на репозиторий, archive - ZIP-проект. */
  kind: 'repo' | 'archive'
  repo: string
  branch: string
  flows: Workflow[]
  runs: RunSummary[]
}
function projectFor(repo: string): Project {
  return {
    id: repo,
    kind: 'repo',
    repo,
    name: USE_MOCKS && repo.endsWith('/training') ? 'Service Desk' : repo.split('/').at(-1)!,
    branch: '—',
    flows: [],
    runs: [],
  }
}

/**
 * Приводит ссылку к https://github.com/owner/repo: убирает `/`, `.git` и `/tree/<ветка>[/<путь>]`
 * (ветка и путь возвращаются отдельно). Не распознанное возвращается как есть для проверки на сервере.
 */
export function normalizeRepoUrl(raw: string): { url: string; branch?: string; subdir?: string } {
  const text = raw.trim()
  const m = /^(https:\/\/(?:www\.)?github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?(?:\/tree\/(.+?))?\/*$/.exec(text)
  if (!m) return { url: text.replace(/\/+$/, '').replace(/\.git$/, '') }
  const url = m[1]!.replace('://www.', '://')
  const [branch, ...rest] = (m[2] ?? '').split('/').filter(Boolean)
  return { url, ...(branch ? { branch } : {}), ...(rest.length ? { subdir: rest.join('/') } : {}) }
}

export async function addRepository(rawRepo: string): Promise<Project> {
  const repo = normalizeRepoUrl(rawRepo).url
  const saved = await api.addRepository(repo)
  if (!saved.repositories.includes(repo)) throw new Error(t('err.repoNotConfirmed'))
  return projectFor(repo)
}

export const zipProjectId = (workflowId: string) => 'zip:' + workflowId

/** Проекты из репозиториев, сценариев и запусков: ссылки - проекты-репозитории, сценарии с `project` - ZIP-проекты. */
export function deriveProjects(repositories: string[], flows: Workflow[], runs: RunSummary[]): Project[] {
  const projects = new Map(repositories.map(repo => [repo, projectFor(repo)]))
  for (const workflow of flows) {
    if (workflow.project?.kind === 'archive') {
      const id = zipProjectId(workflow.id)
      projects.set(id, {
        id, kind: 'archive', repo: '', branch: '—', name: workflow.project.name, flows: [workflow],
        runs: runs.filter(run => run.workflowId === workflow.id),
      })
      continue
    }
    const source = workflow.nodes.find(node => node.type === 'source.repo')
    const project = projects.get(String(source?.params.url ?? ''))
    if (!project) continue
    project.flows.push(workflow)
    const branch = source?.params.branch
    if (project.flows.length === 1 && typeof branch === 'string' && branch) project.branch = branch
  }
  for (const run of runs) {
    if (run.repoUrl) projects.get(run.repoUrl)?.runs.push(run)
  }
  for (const project of projects.values()) {
    project.runs.sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt))
  }
  return [...projects.values()]
}

export async function loadProjects(): Promise<Project[]> {
  const [{ repositories }, summaries, runs] = await Promise.all([
    api.getRepositories(), api.listWorkflows(), api.listRuns(),
  ])
  return deriveProjects(repositories, await Promise.all(summaries.map(w => api.getWorkflow(w.id))), runs)
}

/** Последний загруженный архив ZIP-проекта: повторный запуск не требует новой загрузки. */
export const lastUploadId = (p: Project) => p.runs.find(r => r.uploadId)?.uploadId ?? undefined

export const zipName = (file: string) => file.replace(/\.zip$/i, '').trim().slice(0, 80) || 'ZIP'

/** ZIP-проект: загрузка → сценарий «ZIP + AI-отчёт» проекта → первый запуск. Возвращает id запуска. */
export async function createZipProject(file: File, name: string): Promise<string> {
  const { uploadId } = await api.upload(file)
  const title = name.trim().slice(0, 80) || zipName(file.name)
  const flow = await api.copyTemplate('zip-ai', { name: title, uploadId, project: { kind: 'archive', name: title } })
  return (await api.runWorkflow(flow.id, { source: { kind: 'upload', uploadId } })).runId
}

/** Новая версия архива в тот же ZIP-проект: загрузка и запуск того же сценария. */
export async function uploadNewVersion(p: Project, file: File): Promise<string> {
  const flow = p.flows.find(w => w.nodes.some(n => n.type === 'trigger.manual'))
  if (!flow) throw new Error(t('zip.noFlow'))
  const { uploadId } = await api.upload(file)
  return (await api.runWorkflow(flow.id, { source: { kind: 'upload', uploadId } })).runId
}
export const lastReport = (p: Project) => p.runs.find((r) => r.status === 'SUCCESS' || r.status === 'PARTIAL')
export function download(name: string, body: string, type: string) {
  const url = URL.createObjectURL(new Blob([body], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}
