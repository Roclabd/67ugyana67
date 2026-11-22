import { useState } from 'react'
import { api, ApiError } from '../../api/client'
import { useAction, useApi } from '../../api/useApi'
import type { GraphError, PublishTemplateRequest } from '../../api/types'
import {
  AsyncView,
  Card,
  Empty,
  ErrorBox,
  Page,
} from '../../ui'
import { t } from '../../i18n'

export interface TemplatesScreenProps {
  /** Вызвать после успешного копирования шаблона — откроется редактор нового сценария. */
  onOpenWorkflow: (workflowId: string) => void
}

export function TemplatesScreen({ onOpenWorkflow }: TemplatesScreenProps) {
  const templates = useApi(() => api.listTemplates(), [])
  const workflows = useApi(() => api.listWorkflows(), [])

  const [selectedWorkflowId, setSelectedWorkflowId] = useState('')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [graphErrors, setGraphErrors] = useState<GraphError[]>([])
  const [published, setPublished] = useState(false)

  const copy = useAction((templateId: string) => api.copyTemplate(templateId))
  const publish = useAction(async (request: PublishTemplateRequest) => {
    setGraphErrors([])
    try {
      return await api.publishTemplate(request)
    } catch (error) {
      if (error instanceof ApiError) setGraphErrors(error.graphErrors)
      throw error
    }
  })

  async function handleCopy(templateId: string) {
    const workflow = await copy.run(templateId)
    if (workflow) onOpenWorkflow(workflow.id)
  }

  async function handlePublish() {
    const workflowId = selectedWorkflowId || (workflows.state.status === 'ready' ? workflows.state.data[0]?.id : undefined)
    if (!workflowId || !name.trim()) return

    setPublished(false)
    const result = await publish.run({
      workflowId,
      name: name.trim(),
      description: description.trim(),
    })
    if (result) {
      setPublished(true)
      setName('')
      setDescription('')
      void templates.reload()
    }
  }

  return (
    <Page
      title={t('tpl.title')}
      subtitle={t('tpl.sub')}
    >
      {copy.error && <ErrorBox error={copy.error} />}
      {publish.error && (
        <div className="alert alert--error">
          <div className="alert__title">{t('tpl.pubFail')}</div>
          {publish.error}
          {graphErrors.length > 0 && (
            <ul>
              {graphErrors.map((item, index) => (
                <li key={index}>
                  {item.nodeId ? t('tpl.node', { id: item.nodeId }) : ''}{item.message}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {published && (
        <div className="alert alert--info">
          <div className="alert__title">{t('tpl.published')}</div>
        </div>
      )}

      <AsyncView state={templates.state} onRetry={templates.reload}>
        {(items) => items.length === 0 ? (
          <Card>
            <Empty text={t('tpl.none')} />
          </Card>
        ) : (
          <div className="grid">
            {items.map((template) => (
              <Card key={template.id} title={template.name}>
                <div className="stack">
                  <p>{template.description}</p>
                  <div className="row">
                    {template.tags.map((tag) => (
                      <span className="badge badge--neutral" key={tag}>{tag}</span>
                    ))}
                  </div>
                  <p className="muted">{t('tpl.meta', { n: template.nodeCount, a: template.author })}</p>
                  <div>
                    <button
                      className="btn btn--primary"
                      type="button"
                      disabled={copy.pending}
                      onClick={() => void handleCopy(template.id)}
                    >
                      {copy.pending ? t('tpl.copying') : t('tpl.copy')}
                    </button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </AsyncView>

      <Card title={t('tpl.publishTitle')}>
        <AsyncView state={workflows.state} onRetry={workflows.reload}>
          {(items) => items.length === 0 ? (
            <Empty text={t('tpl.createFirst')} />
          ) : (
            <div className="stack">
              <label className="field">
                <span className="field__label">{t('tpl.workflow')}</span>
                <select
                  className="select"
                  value={selectedWorkflowId || items[0].id}
                  onChange={(event) => setSelectedWorkflowId(event.target.value)}
                >
                  {items.map((workflow) => (
                    <option key={workflow.id} value={workflow.id}>
                      {workflow.name} · v{workflow.version}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span className="field__label">{t('tpl.name')}</span>
                <input
                  className="input"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder={t('tpl.namePh')}
                />
              </label>
              <label className="field">
                <span className="field__label">{t('tpl.desc')}</span>
                <textarea
                  className="textarea"
                  value={description}
                  onChange={(event) => setDescription(event.target.value)}
                  placeholder={t('tpl.descPh')}
                  rows={3}
                />
              </label>
              <div>
                <button
                  className="btn btn--primary"
                  type="button"
                  disabled={publish.pending || !name.trim() || items.length === 0}
                  onClick={() => void handlePublish()}
                >
                  {publish.pending ? t('tpl.publishing') : t('tpl.publish')}
                </button>
              </div>
            </div>
          )}
        </AsyncView>
      </Card>
    </Page>
  )
}
