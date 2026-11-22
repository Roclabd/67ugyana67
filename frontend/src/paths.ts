/** Все пути приложения — в одном месте. */
export const paths = {
  workflows: () => '/workflows',
  newWorkflow: () => '/workflows/new',
  workflow: (id: string) => `/workflows/${encodeURIComponent(id)}`,
  run: (runId: string) => `/runs/${encodeURIComponent(runId)}`,
  report: (runId: string) => `/runs/${encodeURIComponent(runId)}/report`,
  history: (workflowId?: string) => (workflowId ? `/history?workflowId=${encodeURIComponent(workflowId)}` : '/history'),
  templates: () => '/templates',
  ci: () => '/ci',
  settings: () => '/settings',
}
