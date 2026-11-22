import { useEffect, useState } from 'react'
import { api } from '../../api/client'
import { useApi } from '../../api/useApi'
import type { CiKind } from '../../api/types'
import { AsyncView, Card, Empty, ErrorBox, Page } from '../../ui'
import { t } from '../../i18n'

export interface CiScreenProps {
  /** Сценарий, выбранный по умолчанию (из адреса), если есть. */
  initialWorkflowId?: string
  initialKind?: CiKind
}

export function CiScreen({ initialWorkflowId, initialKind = 'github' }: CiScreenProps) {
  const workflows = useApi(() => api.listWorkflows(), [])
  const availableWorkflows = workflows.state.status === 'ready' ? workflows.state.data : []
  const initialSelection = availableWorkflows.some((item) => item.id === initialWorkflowId)
    ? initialWorkflowId
    : availableWorkflows[0]?.id ?? ''
  const [selectedWorkflowId, setSelectedWorkflowId] = useState(initialWorkflowId ?? '')
  const [kind, setKind] = useState<CiKind>(initialKind)
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState<string | null>(null)
  const workflowId = availableWorkflows.some((item) => item.id === selectedWorkflowId)
    ? selectedWorkflowId
    : initialSelection

  const workflow = useApi(
    () => workflowId ? api.getWorkflow(workflowId) : Promise.resolve(null),
    [workflowId],
  )

  const yaml = useApi(
    () => workflowId ? api.getCiConfig(workflowId, kind) : Promise.resolve(''),
    [workflowId, kind],
  )

  const missingWebhook = workflow.state.status === 'ready'
    && workflow.state.data !== null
    && !workflow.state.data.nodes.some((node) => node.type === 'trigger.webhook')

  useEffect(() => {
    if (!copied) return
    const timeout = window.setTimeout(() => setCopied(false), 2000)
    return () => window.clearTimeout(timeout)
  }, [copied])

  async function handleCopy() {
    if (yaml.state.status !== 'ready' || !workflowId) return
    setCopyError(null)
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error(t('ci.noClipboard'))
      }
      await navigator.clipboard.writeText(yaml.state.data)
      setCopied(true)
    } catch (error) {
      setCopyError(error instanceof Error ? error.message : t('ci.copyFail'))
    }
  }

  const tokenLocation = kind === 'github'
    ? 'Settings → Secrets and variables → Actions → Secrets'
    : t('ci.gitlabSecret')
  const urlLocation = kind === 'github'
    ? 'Settings → Secrets and variables → Actions → Variables'
    : 'Settings → CI/CD → Variables'

  return (
    <Page
      title={t('ci.title')}
      subtitle={t('ci.sub')}
    >
      <AsyncView state={workflows.state} onRetry={workflows.reload}>
        {(items) => items.length === 0 ? (
          <Card>
            <Empty text={t('ci.createFirst')} />
          </Card>
        ) : (
          <div className="stack">
            <Card title={t('ci.params')}>
              <div className="stack">
                <label className="field">
                  <span className="field__label">{t('tpl.workflow')}</span>
                  <select
                    className="select"
                    value={workflowId}
                    onChange={(event) => {
                      setSelectedWorkflowId(event.target.value)
                      setCopied(false)
                      setCopyError(null)
                    }}
                  >
                    {items.map((workflow) => (
                      <option key={workflow.id} value={workflow.id}>{workflow.name}</option>
                    ))}
                  </select>
                </label>
                <div className="row">
                  <button
                    className={kind === 'github' ? 'btn btn--primary' : 'btn'}
                    type="button"
                    onClick={() => {
                      setKind('github')
                      setCopied(false)
                      setCopyError(null)
                    }}
                  >
                    GitHub Actions
                  </button>
                  <button
                    className={kind === 'gitlab' ? 'btn btn--primary' : 'btn'}
                    type="button"
                    onClick={() => {
                      setKind('gitlab')
                      setCopied(false)
                      setCopyError(null)
                    }}
                  >
                    GitLab CI
                  </button>
                </div>
              </div>
            </Card>

            <Card
              title={t('ci.pipeline')}
              actions={
                <button
                  className="btn btn--primary"
                  type="button"
                  disabled={yaml.state.status !== 'ready' || !workflowId}
                  onClick={() => void handleCopy()}
                >
                  {copied ? t('ci.copied') : t('ci.copy')}
                </button>
              }
            >
              {missingWebhook && (
                <div className="alert alert--warn">
                  <div className="alert__title">{t('ci.cannot')}</div>
                  {t('ci.needWebhook')}
                </div>
              )}
              {copyError && <ErrorBox error={copyError} />}
              <AsyncView state={yaml.state} onRetry={yaml.reload}>
                {(text) => text ? (
                  <pre className="mono">{text}</pre>
                ) : (
                  <Empty text={t('ci.pickWf')} />
                )}
              </AsyncView>
            </Card>

            <Card title={t('ci.how')}>
              <ol>
                <li>
                  {t('ci.s1a')} <span className="mono">CI_TOKEN</span> {t('ci.s1b')}
                  <span className="mono"> CI_TOKEN </span> {t('ci.s1c')} {tokenLocation}.
                </li>
                <li>
                  {t('ci.s2a')} <span className="mono">WORKFLOW_URL</span> {t('ci.s2b')}
                  {t('ci.path')} {urlLocation}.
                </li>
                <li>
                  {t('ci.s3a')} <code>CI_RULES_VERSION</code> {t('ci.s3b')}
                </li>
                <li>
                  {t('ci.s4')} <span className="mono">
                    {kind === 'github' ? '.github/workflows/security.yml' : '.gitlab-ci.yml'}
                  </span>.
                </li>
              </ol>
              <p className="muted">
                {t('ci.names')}
              </p>
              <div className="alert alert--info">
                {t('ci.gate')}
              </div>
            </Card>
          </div>
        )}
      </AsyncView>
    </Page>
  )
}
