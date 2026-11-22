import { describe, expect, it } from 'vitest'
import { normalizeRepoUrl } from './data'

describe('normalizeRepoUrl', () => {
  const url = 'https://github.com/example-org/training'
  it('убирает слэш и .git', () => {
    for (const v of [url, `${url}/`, `${url}.git`, `${url}.git/`, ` ${url} `]) expect(normalizeRepoUrl(v)).toEqual({ url })
  })
  it('разбирает /tree/<ветка>[/<путь>]', () => {
    expect(normalizeRepoUrl(`${url}/tree/main`)).toEqual({ url, branch: 'main' })
    expect(normalizeRepoUrl(`${url}/tree/dev/sample-project/app/`)).toEqual({ url, branch: 'dev', subdir: 'sample-project/app' })
  })
  it('чужое оставляет серверной проверке', () => {
    expect(normalizeRepoUrl('https://gitlab.com/a/b.git/').url).toBe('https://gitlab.com/a/b')
  })
})
