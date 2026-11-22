// Генератор фикстуры отчёта для фронта из эталона авторов набора.
// node gen-report-fixture.mjs <repo-root>
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join } from 'node:path'

const root = process.argv[2]
const gt = JSON.parse(readFileSync(join(root, 'fixtures/training/ground-truth/training-findings.json'), 'utf8'))
const outDir = join(root, 'frontend/src/api/fixtures')
mkdirSync(outDir, { recursive: true })

const sha = (s) => createHash('sha256').update(s).digest('hex')

const RULES = {
  password: 'secret.literal.password',
  'api-key': 'secret.literal.api-key',
  'configuration-token': 'secret.config.token',
  'secret-fallback': 'secret.fallback.literal',
  'recoverable-token': 'secret.const-fold.token',
  'sql-injection': 'sast.sql.taint-to-jdbc',
  'tls-verification': 'sast.tls.hostname-verifier-true',
  'credentialed-cors': 'sast.cors.wildcard-with-credentials',
  'route-authorization': 'sast.route.shadowed-permit-all',
  'object-authorization': 'sast.idor.missing-owner-filter',
}
const TITLES = {
  password: 'Пароль в коде',
  'api-key': 'API-ключ в коде',
  'configuration-token': 'Токен в конфигурации',
  'secret-fallback': 'Секрет как значение по умолчанию',
  'recoverable-token': 'Токен, склеенный из частей',
  'sql-injection': 'SQL-инъекция',
  'tls-verification': 'Отключена проверка имени хоста TLS',
  'credentialed-cors': 'CORS: любой origin вместе с credentials',
  'route-authorization': 'Маршрут открыт раньше строгого правила',
  'object-authorization': 'Чтение чужого объекта по id (IDOR)',
}
const MASKS = {
  'A-SEC-01': 'codeguard_••••••••',
  'A-SEC-02': 'codeguard_••••••••',
  'A-SEC-03': 'Bearer ••••••••',
  'A-SEC-04': 'codeguard_••••••••',
  'A-SEC-05': 'codeguard_••••••••',
}

function evidence(f) {
  const ev = [{ path: f.path, line: f.line, ...(f.endLine && f.endLine !== f.line ? { endLine: f.endLine } : {}), note: noteFor(f) }]
  for (const a of f.alternateLocations ?? []) ev.push({ path: a.path, line: a.line, note: 'связанное место' })
  return ev
}
function noteFor(f) {
  if (f.category === 'SCA') return `${f.group}:${f.artifact}:${f.version} — объявление зависимости`
  if (f.category === 'SECRET') return 'литерал секрета (значение замаскировано)'
  return 'проблемное выражение'
}

let i = 0
const findings = gt.findings.map((f) => {
  i++
  const base = {
    id: `f-${String(i).padStart(2, '0')}`,
    fingerprint: sha(f.id + f.path + f.line),
    category: f.category,
    path: f.path,
    severity: f.severity,
    description: f.description,
    remediation: f.remediation,
    evidence: evidence(f),
  }
  if (f.category === 'SCA') {
    const fixed = (f.affected.match(/→ `([^`]+)`/) ?? [])[1]
    return {
      ...base,
      rule: 'sca.vulnerable-version-range',
      title: `${f.group}:${f.artifact} ${f.version} — ${f.advisoryIds[0]}`,
      line: f.line,
      group: f.group,
      artifact: f.artifact,
      version: f.version,
      advisoryId: f.advisoryIds[0],
      fixedVersions: fixed ? [fixed] : [],
      ai: aiFor(f, i),
    }
  }
  return {
    ...base,
    class: f.class,
    line: f.line,
    ...(f.endLine !== f.line ? { endLine: f.endLine } : {}),
    rule: RULES[f.class],
    title: TITLES[f.class],
    ...(f.category === 'SECRET' ? { secretMasked: MASKS[f.id] } : {}),
    ai: aiFor(f, i),
  }
})

// Разные статусы AI, чтобы экран показывал все варианты.
function aiFor(f, n) {
  if (n === 4) return { status: 'NOT_RECEIVED' }
  if (n === 12) return { status: 'REJECTED_BY_VALIDATOR' }
  return {
    status: 'OK',
    explanation: `Простыми словами: ${f.description.replace(/`/g, '')}`,
    impact: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'Злоумышленник может получить доступ к данным клиентов.' : 'Повышает риск компрометации при сочетании с другими уязвимостями.',
    fixSteps: [f.remediation.replace(/`/g, '')],
    usefulnessChecks: { parsesAsKotlin: true, sameIdentifier: true, fixPattern: n !== 7 },
  }
}

const dismissed = [
  { rule: 'secret.literal.api-key', path: 'README.md', line: 9, reason: 'Плейсхолдер в документации (YOUR_API_KEY)' },
  { rule: 'secret.config.token', path: 'src/main/resources/application.yml', line: 17, reason: 'Подстановка из окружения ${INVENTORY_TOKEN} без значения по умолчанию' },
  { rule: 'secret.fallback.literal', path: 'src/main/kotlin/lab/servicedesk/config/RepairAccounts.kt', line: 17, reason: 'Fallback — случайное значение UUID, не литерал' },
  { rule: 'secret.config.token', path: 'src/main/kotlin/lab/servicedesk/pickup/LegacyIntake.kt', line: 31, reason: '@Value без значения по умолчанию' },
]
const dismissedSca = [
  { rule: 'sca.vulnerable-version-range', path: 'build.gradle.kts', line: 39, reason: 'commons-lang3 3.20.0 вне уязвимого диапазона CVE-2025-48924' },
  { rule: 'sca.scope.declared-only', path: 'gradle.lockfile', reason: 'snakeyaml 2.5 и kotlin-stdlib 2.2.21 — транзитивные, вне области' },
]
const dismissedSast = [
  { rule: 'sast.sql.taint-to-jdbc', path: 'src/main/kotlin/lab/servicedesk/repair/RepairLookupController.kt', line: 17, reason: 'Параметризованный запрос: ? и отдельный аргумент JDBC' },
  { rule: 'sast.route.shadowed-permit-all', path: 'src/main/kotlin/lab/servicedesk/config/RepairSecurity.kt', line: 17, reason: 'permitAll на публичный каталог услуг, строгого правила не затеняет' },
  { rule: 'sast.tls.hostname-verifier-true', path: 'src/main/kotlin/lab/servicedesk/integration/ManualsHttpsClient.kt', line: 7, reason: 'Стандартная проверка TLS' },
]
const rulesOf = (cat) => [...new Set(findings.filter((f) => f.category === cat).map((f) => f.rule))].sort()

const complete = {
  runId: 'run-0001',
  workflowId: 'wf-full',
  workflowVersion: 3,
  inputHash: sha('sample-project'),
  rulesVersion: '2026.11.20-1',
  coverage: {
    status: 'COMPLETE',
    byAnalyzer: {
      n4: { status: 'COMPLETE', filesAnalyzed: 21, filesSkipped: [], rulesApplied: rulesOf('SECRET'), unresolved: [], dismissed },
      n5: { status: 'COMPLETE', filesAnalyzed: 3, filesSkipped: [], rulesApplied: rulesOf('SCA'), unresolved: [], dismissed: dismissedSca },
      n6: { status: 'COMPLETE', filesAnalyzed: 17, filesSkipped: [], rulesApplied: rulesOf('SAST'), unresolved: [], dismissed: dismissedSast },
    },
  },
  findings,
  ai: {
    status: 'PARTIAL',
    provider: 'groq',
    model: 'llama-3.3-70b-versatile',
    summary: 'Главные риски: открытый экспорт выдачи и чтение чужих заявок (одна история доступа), SQL-инъекция в поиске по метке, критичная commons-text 1.9. Начать с обновления commons-text и закрытия /api/pickup/export.',
    validator: { responses: 15, schemaFailures: 1, rejectedFindingRefs: 1, rejectedCves: 2 },
  },
}

// Вариант с неполным анализом: показывает, что «мало находок» ≠ «чисто».
const partialFindings = findings.filter((f) => f.category !== 'SAST').map((f) => ({ ...f, ai: { status: 'NOT_RECEIVED' } }))
const partial = {
  ...complete,
  runId: 'run-0002',
  coverage: {
    status: 'PARTIAL',
    byAnalyzer: {
      ...complete.coverage.byAnalyzer,
      n5: {
        ...complete.coverage.byAnalyzer.n5,
        status: 'PARTIAL',
        unresolved: [{ kind: 'version', path: 'build.gradle.kts', line: 40, subject: 'org.example:legacy-client', reason: 'Свойство legacyClientVersion не определено' }],
      },
      n6: {
        ...complete.coverage.byAnalyzer.n6,
        status: 'FAILED',
        filesAnalyzed: 0,
        filesSkipped: [{ path: 'src/main/kotlin/lab/servicedesk/config/RepairSecurity.kt', line: 12, reason: 'Ошибка разбора PSI' }],
      },
    },
  },
  findings: partialFindings,
  ai: { status: 'NOT_RECEIVED', provider: 'groq', model: 'llama-3.3-70b-versatile', validator: { responses: 0, schemaFailures: 0, rejectedFindingRefs: 0, rejectedCves: 0 } },
}

writeFileSync(join(outDir, 'report-complete.json'), JSON.stringify(complete, null, 2) + '\n')
writeFileSync(join(outDir, 'report-partial.json'), JSON.stringify(partial, null, 2) + '\n')
console.log('ok', findings.length, partialFindings.length)
