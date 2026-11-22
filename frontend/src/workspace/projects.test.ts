import { describe, expect, it } from 'vitest'
import type { RunSummary, Workflow } from '../api/types'
import { deriveProjects, lastUploadId } from './data'

const run = (runId: string, workflowId: string, startedAt: string, extra: Partial<RunSummary> = {}) =>
  ({ runId, workflowId, status: 'SUCCESS', startedAt, ...extra }) as RunSummary
const repoFlow = { id: 'w1', name: 'r', version: 1, edges: [], nodes: [{ id: 's', type: 'source.repo', params: { url: 'https://github.com/a/b' } }] } as unknown as Workflow
const zipFlow = { id: 'w2', name: 'z', version: 1, edges: [], nodes: [{ id: 's', type: 'source.archive', params: {} }], project: { kind: 'archive', name: 'Demo' } } as unknown as Workflow

describe('проекты', () => {
  it('выводит проект-репозиторий и ZIP-проект', () => {
    const list = deriveProjects(['https://github.com/a/b'], [repoFlow, zipFlow], [
      run('r1', 'w1', '2026-01-01', { repoUrl: 'https://github.com/a/b' }),
      run('z1', 'w2', '2026-01-01', { uploadId: 'u1' }),
      run('z2', 'w2', '2026-01-02', { uploadId: 'u2' }),
    ])
    expect(list.map((p) => [p.kind, p.name])).toEqual([['repo', 'b'], ['archive', 'Demo']])
    expect(list[0]!.runs).toHaveLength(1)
    expect(list[1]!.runs.map((r) => r.runId)).toEqual(['z2', 'z1'])
  })
  it('последний архив берётся из свежего запуска', () => {
    const [p] = deriveProjects([], [zipFlow], [run('z1', 'w2', '2026-01-01', { uploadId: 'u1' }), run('z2', 'w2', '2026-01-02', { uploadId: 'u2' })])
    expect(lastUploadId(p!)).toBe('u2')
  })
})
