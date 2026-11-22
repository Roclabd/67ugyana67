/** Тестовый код — те же признаки, что у SECRET (isSecretScanExcluded): папки test/tests/… и файлы *Test.kt. */
const TEST_DIRS = new Set(['test', 'tests', 'testfixtures', 'integrationtest', 'androidtest'])

export function isTestPath(path: string): boolean {
  const parts = path.toLowerCase().split('/')
  const name = parts[parts.length - 1]
  return parts.slice(0, -1).some((p) => TEST_DIRS.has(p)) || name.endsWith('test.kt') || name.endsWith('tests.kt')
}

/**
 * Секрет-кандидат в тестовом коде. SECRET не считает его уязвимостью приложения, но эксперт назвал плюсом
 * «найти и пометить, что это нужно вынести». Отметка о самом файле (secret.scope) кандидатом не является.
 */
export function isTestSecret(d: { path: string; rule: string; reason: string }): boolean {
  return d.rule.startsWith('secret') && d.rule !== 'secret.scope' && isTestPath(d.path) &&
    (d.reason === 'excluded-source' || d.reason === 'test-source')
}
