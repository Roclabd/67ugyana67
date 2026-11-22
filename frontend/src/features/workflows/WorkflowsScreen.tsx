/**
 * ЭКРАН-ОБРАЗЕЦ. Экраны A копируют его структуру:
 *  1) пропсы — только данные и колбэки навигации (роутер в экран не импортируется);
 *  2) данные — через useApi(() => api.метод(), [зависимости]);
 *  3) AsyncView сам показывает загрузку и ошибку, экран отдельно обрабатывает «пусто»;
 *  4) действия — через useAction: кнопка показывает ожидание, ошибку сервера выводим как есть;
 *  5) только компоненты из src/ui и классы из styles.css.
 */
import { api } from '../../api/client'
import { useAction, useApi } from '../../api/useApi'
import type { WorkflowSummary } from '../../api/types'
import { AsyncView, Card, Empty, ErrorBox, Page } from '../../ui'
import { formatDateTime } from '../../ui/format'
import { t } from '../../i18n'

export interface WorkflowsScreenProps {
  onOpenWorkflow: (workflowId: string) => void
  onOpenRun: (runId: string) => void
  onCreate: () => void
}

export function WorkflowsScreen({ onOpenWorkflow, onOpenRun, onCreate }: WorkflowsScreenProps) {
  const workflows = useApi(() => api.listWorkflows(), [])
  const run = useAction((id: string) => api.runWorkflow(id))

  async function handleRun(wf: WorkflowSummary) {
    const started = await run.run(wf.id)
    if (started) onOpenRun(started.runId)
  }

  return (
    <Page
      title={t('wf.title')}
      subtitle={t('wf.sub')}
      actions={<button className="btn btn--primary" onClick={onCreate}>{t('sf.newWorkflow.n')}</button>}
    >
      {run.error && <ErrorBox error={run.error} />}
      <AsyncView state={workflows.state} onRetry={workflows.reload}>
        {(items) =>
          items.length === 0 ? (
            <Card>
              <Empty text={t('wf.none')}>
                <p><button className="btn btn--primary" onClick={onCreate}>{t('wf.first')}</button></p>
              </Empty>
            </Card>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>{t('tpl.name')}</th>
                  <th>{t('wf.version')}</th>
                  <th>{t('wf.changed')}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {items.map((wf) => (
                  <tr key={wf.id} className="clickable" onClick={() => onOpenWorkflow(wf.id)}>
                    <td>{wf.name}</td>
                    <td>v{wf.version}</td>
                    <td>{formatDateTime(wf.updatedAt)}</td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn"
                        disabled={run.pending}
                        onClick={(e) => {
                          e.stopPropagation()
                          void handleRun(wf)
                        }}
                      >
                        {t('ed.runShort')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        }
      </AsyncView>
    </Page>
  )
}
