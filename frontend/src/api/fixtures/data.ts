import type {
  CiRunResult,
  LlmSettings,
  Report,
  RouteMapArtifact,
  RunSummary,
  Template,
  Workflow,
} from '../types'
import reportComplete from './report-complete.json'
import reportPartial from './report-partial.json'
import routeMap from './route-map.json'

/**
 * Фикстуры для режима моков. Формы — docs/API.md и contracts/finding.schema.json.
 * Отчёты report-*.json собраны из эталона авторов набора скриптом frontend/scripts/gen-report-fixture.mjs.
 * Когда бэк заработает, заменяем на снятые с него ответы (тот же формат).
 */

export const reportCompleteFixture = reportComplete as Report
export const reportPartialFixture = reportPartial as Report

/** Сценарий «Полная проверка»: кнопка → клон → разбор → 3 анализатора → объединить → AI → отчёт → if critical → Telegram. */
export const workflowFullFixture: Workflow = {
  id: 'wf-full',
  name: 'Полная проверка перед релизом',
  version: 3,
  nodes: [
    { id: 'n1', type: 'trigger.manual', params: {}, position: { x: 0, y: 160 } },
    {
      id: 'n2',
      type: 'source.repo',
      params: { url: 'https://github.com/example-org/training', branch: 'main', subdir: 'sample-project' },
      position: { x: 220, y: 160 },
    },
    { id: 'n3', type: 'analyzer.parse', params: {}, position: { x: 460, y: 160 } },
    { id: 'n4', type: 'analyzer.secret', params: { minSeverity: 'LOW', includeTests: true }, position: { x: 700, y: 20 } },
    { id: 'n5', type: 'analyzer.sca', params: { minSeverity: 'LOW' }, position: { x: 700, y: 160 } },
    { id: 'n6', type: 'analyzer.sast', params: { minSeverity: 'LOW' }, position: { x: 700, y: 300 } },
    { id: 'n11', type: 'output.route-map', params: {}, position: { x: 700, y: 440 } },
    { id: 'n7', type: 'logic.merge', params: { dedupe: true }, position: { x: 960, y: 160 } },
    { id: 'n8', type: 'ai.explain', params: { language: 'ru', maxFindings: 50 }, position: { x: 1180, y: 160 } },
    { id: 'n9', type: 'output.report', params: {}, position: { x: 1400, y: 160 } },
    {
      id: 'n10',
      type: 'notify.telegram',
      params: { token: '••••', chatId: '-100123' },
      position: { x: 1620, y: 160 },
    },
  ],
  edges: [
    { id: 'e1', from: { node: 'n1', port: 'out' }, to: { node: 'n2', port: 'in' } },
    { id: 'e2', from: { node: 'n2', port: 'workspace' }, to: { node: 'n3', port: 'workspace' } },
    { id: 'e3', from: { node: 'n3', port: 'model' }, to: { node: 'n4', port: 'model' } },
    { id: 'e4', from: { node: 'n3', port: 'model' }, to: { node: 'n5', port: 'model' } },
    { id: 'e5', from: { node: 'n3', port: 'model' }, to: { node: 'n6', port: 'model' } },
    { id: 'e12', from: { node: 'n3', port: 'model' }, to: { node: 'n11', port: 'model' } },
    { id: 'e6', from: { node: 'n4', port: 'findings' }, to: { node: 'n7', port: 'a' } },
    { id: 'e7', from: { node: 'n5', port: 'findings' }, to: { node: 'n7', port: 'b' } },
    { id: 'e8', from: { node: 'n6', port: 'findings' }, to: { node: 'n7', port: 'c' } },
    { id: 'e9', from: { node: 'n7', port: 'findings' }, to: { node: 'n8', port: 'findings' } },
    { id: 'e10', from: { node: 'n8', port: 'findings' }, to: { node: 'n9', port: 'findings' } },
    { id: 'e11', from: { node: 'n9', port: 'report' }, to: { node: 'n10', port: 'report' } },
  ],
}

/** Ответ ноды output.route-map (C8) на учебном проекте — снят с сервера (порт report). */
export const routeMapArtifactFixture = routeMap as RouteMapArtifact

export const workflowSecretsDailyFixture: Workflow = {
  id: 'wf-secrets-daily',
  name: 'Секреты каждый день в 14:00 на почту',
  version: 1,
  nodes: [
    { id: 'n1', type: 'trigger.cron', params: { cron: '0 0 14 * * *', timezone: 'Europe/Moscow' }, position: { x: 0, y: 0 } },
    { id: 'n2', type: 'source.repo', params: { url: 'https://github.com/example-org/training', branch: 'main', subdir: 'sample-project' }, position: { x: 220, y: 0 } },
    { id: 'n3', type: 'analyzer.parse', params: {}, position: { x: 440, y: 0 } },
    { id: 'n4', type: 'analyzer.secret', params: { minSeverity: 'LOW', includeTests: true }, position: { x: 660, y: 0 } },
    { id: 'n5', type: 'output.report', params: {}, position: { x: 880, y: 0 } },
    { id: 'n6', type: 'notify.smtp', params: { host: 'smtp.example.org', port: 587, username: 'bot', password: '••••', to: 'sec@example.org' }, position: { x: 1100, y: 0 } },
  ],
  edges: [
    { id: 'e1', from: { node: 'n1', port: 'out' }, to: { node: 'n2', port: 'in' } },
    { id: 'e2', from: { node: 'n2', port: 'workspace' }, to: { node: 'n3', port: 'workspace' } },
    { id: 'e3', from: { node: 'n3', port: 'model' }, to: { node: 'n4', port: 'model' } },
    { id: 'e4', from: { node: 'n4', port: 'findings' }, to: { node: 'n5', port: 'findings' } },
    { id: 'e5', from: { node: 'n5', port: 'report' }, to: { node: 'n6', port: 'report' } },
  ],
}

export const workflowsFixture: Workflow[] = [workflowFullFixture, workflowSecretsDailyFixture]

function countsOf(report: Report) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const f of report.findings) c[f.severity]++
  return c
}

export const runsFixture: RunSummary[] = [
  {
    runId: 'run-0002',
    workflowId: 'wf-full',
    workflowName: 'Полная проверка перед релизом',
    status: 'PARTIAL',
    coverageStatus: 'PARTIAL',
    counts: countsOf(reportPartialFixture),
    trigger: 'manual',
    startedAt: '2026-11-21T10:12:00Z',
    finishedAt: '2026-11-21T10:12:41Z',
  },
  {
    runId: 'run-0001',
    workflowId: 'wf-full',
    workflowName: 'Полная проверка перед релизом',
    status: 'SUCCESS',
    coverageStatus: 'COMPLETE',
    counts: countsOf(reportCompleteFixture),
    trigger: 'manual',
    startedAt: '2026-11-21T09:30:00Z',
    finishedAt: '2026-11-21T09:30:37Z',
  },
  {
    runId: 'run-0000',
    workflowId: 'wf-secrets-daily',
    workflowName: 'Секреты каждый день в 14:00 на почту',
    status: 'FAILED',
    coverageStatus: 'FAILED',
    counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    trigger: 'cron',
    startedAt: '2026-11-20T14:00:00Z',
    finishedAt: '2026-11-20T14:00:03Z',
  },
]

export const templatesFixture: Template[] = [
  {
    id: 'tpl-full',
    name: 'Полная проверка перед релизом',
    description: 'Секреты, зависимости и код Kotlin/Spring, объяснения AI, отчёт в Telegram.',
    tags: ['SECRET', 'SCA', 'SAST', 'AI', 'Telegram'],
    nodeCount: workflowFullFixture.nodes.length,
    author: 'Команда',
    workflow: { name: workflowFullFixture.name, nodes: workflowFullFixture.nodes, edges: workflowFullFixture.edges },
  },
  {
    id: 'tpl-secrets-daily',
    name: 'Секреты каждый день в 14:00 на почту',
    description: 'Ежедневная проверка на секреты с отчётом на почту.',
    tags: ['SECRET', 'расписание', 'SMTP'],
    nodeCount: workflowSecretsDailyFixture.nodes.length,
    author: 'Команда',
    workflow: { name: workflowSecretsDailyFixture.name, nodes: workflowSecretsDailyFixture.nodes, edges: workflowSecretsDailyFixture.edges },
  },
  {
    id: 'tpl-ci-gate',
    name: 'Проверка в CI с блокировкой',
    description: 'Запуск из пайплайна, сборка падает при critical или неполном анализе.',
    tags: ['CI', 'fail-closed'],
    nodeCount: 6,
    author: 'Команда',
    workflow: { name: 'Проверка в CI с блокировкой', nodes: [], edges: [] },
  },
]

export const llmSettingsFixture: LlmSettings = {
  provider: 'groq',
  baseUrl: 'https://api.groq.com/openai/v1',
  model: 'llama-3.3-70b-versatile',
  apiKeySet: true,
}

export const ciRunFixture: CiRunResult = {
  runId: 'run-0001',
  status: 'SUCCESS',
  coverageStatus: 'COMPLETE',
  counts: countsOf(reportCompleteFixture),
  pass: false,
  reason: 'Найдено critical: 1',
}

/**
 * YAML для CI — дословно ci-examples/*.yml, которые сервер отдаёт из GET /api/ci/workflows/{id}/config,
 * подставляя id сценария вместо WORKFLOW_ID_HERE (мок делает то же самое).
 */
export const ciGithubYamlFixture = "name: Codeguard check\non: [push, pull_request]\npermissions: {}\n\njobs:\n  codeguard-check:\n    runs-on: ubuntu-latest\n    env:\n      WORKFLOW_ID: WORKFLOW_ID_HERE\n      WORKFLOW_URL: ${{ vars.WORKFLOW_URL }}\n      CI_TOKEN: ${{ secrets.CI_TOKEN }}\n      REPOSITORY: ${{ github.event.pull_request.head.repo.full_name || github.repository }}\n      COMMIT_SHA: ${{ github.event.pull_request.head.sha || github.sha }}\n      BRANCH: ${{ github.head_ref || github.ref_name }}\n    steps:\n      - name: Проверка кода\n        shell: bash\n        run: |\n          set -euo pipefail\n          body=$(jq -n --arg url \"https://github.com/$REPOSITORY\" --arg sha \"$COMMIT_SHA\" --arg branch \"$BRANCH\" \\\n            '{repoUrl:$url,commitSha:$sha,branch:$branch}')\n          response=$(curl --fail-with-body --silent --show-error --max-time 140 \\\n            --header \"Authorization: Bearer $CI_TOKEN\" --header \"Content-Type: application/json\" \\\n            --data \"$body\" \"${WORKFLOW_URL%/}/api/ci/workflows/$WORKFLOW_ID/run?wait=true\")\n          jq '{runId,status,coverageStatus,pass,reason}' <<<\"$response\"\n          jq -e '.pass == true' <<<\"$response\" > /dev/null\n"

export const ciGitlabYamlFixture = "codeguard-check:\n  stage: test\n  image: alpine:3.22\n  variables:\n    WORKFLOW_ID: WORKFLOW_ID_HERE\n  before_script:\n    - apk add --no-cache curl jq\n  script:\n    - |\n      set -eu\n      body=$(jq -n --arg url \"${CI_PROJECT_URL}\" --arg sha \"$CI_COMMIT_SHA\" --arg branch \"$CI_COMMIT_REF_NAME\" \\\n        '{repoUrl:$url,commitSha:$sha,branch:$branch}')\n      response=$(curl --fail-with-body --silent --show-error --max-time 140 \\\n        --header \"Authorization: Bearer $CI_TOKEN\" --header \"Content-Type: application/json\" \\\n        --data \"$body\" \"${WORKFLOW_URL%/}/api/ci/workflows/$WORKFLOW_ID/run?wait=true\")\n      printf '%s' \"$response\" | jq '{runId,status,coverageStatus,pass,reason}'\n      printf '%s' \"$response\" | jq -e '.pass == true' > /dev/null\n"

export const reportMarkdownFixture = `# Отчёт запуска run-0001

Покрытие: COMPLETE. Находок: 15 (CRITICAL 1, HIGH 7, MEDIUM 6, LOW 1).

(в режиме моков — сокращённо; полный отчёт строит ReportExporter на бэке)
`
