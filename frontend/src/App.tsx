/**
 * Роутинг и каркас. Экраны получают параметры адреса и колбэки навигации через пропсы,
 * поэтому сами экраны (в том числе зона A) роутер не импортируют.
 */
import { Route, Routes, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { Shell } from './workspace/Shell'
import { RepositoriesSettings } from './workspace/Pages'
import { TelegramSettings } from './workspace/TelegramSettings'
import { EditorScreen } from './editor/EditorScreen'
import { WorkflowsScreen } from './features/workflows/WorkflowsScreen'
import { RunScreen } from './run/RunScreen'
import { CiScreen } from './screens/ci/CiScreen'
import { HistoryScreen } from './screens/history/HistoryScreen'
import { ReportScreen } from './screens/report/ReportScreen'
import { SettingsScreen } from './screens/settings/SettingsScreen'
import { TemplatesScreen } from './screens/templates/TemplatesScreen'
import { paths } from './paths'
import { t, useLang } from './i18n'

export function App() {
  // Подписка на язык: при его смене пересоздаются элементы страниц, переданные в Shell.
  useLang()
  return (
    <Shell
      legacy={
        <Routes>
          <Route path="/workflows" element={<WorkflowsRoute />} />
          <Route path="/workflows/new" element={<EditorRoute />} />
          <Route path="/workflows/:workflowId" element={<EditorRoute />} />
          <Route path="/runs/:runId" element={<RunRoute />} />
          <Route path="/runs/:runId/details" element={<ReportRoute />} />
          <Route path="/history" element={<HistoryRoute />} />
          <Route path="/history/all" element={<HistoryRoute />} />
          <Route path="/templates" element={<TemplatesRoute />} />
          <Route path="/ci" element={<CiRoute />} />
          <Route path="/settings" element={<><SettingsScreen /><RepositoriesSettings /><TelegramSettings /></>} />
          <Route path="*" element={<div className="empty">{t('ui.notFound')}</div>} />
        </Routes>
      }
    />
  )
}

function WorkflowsRoute() {
  const nav = useNavigate()
  return (
    <WorkflowsScreen
      onOpenWorkflow={(id) => nav(paths.workflow(id))}
      onOpenRun={(id) => nav(paths.run(id))}
      onCreate={() => nav(paths.newWorkflow())}
    />
  )
}

function EditorRoute() {
  const { workflowId } = useParams()
  const nav = useNavigate()
  return (
    <EditorScreen
      key={workflowId ?? 'new'}
      workflowId={workflowId}
      onSaved={(id) => nav(paths.workflow(id), { replace: true })}
      onOpenRun={(id) => nav(paths.run(id))}
    />
  )
}

function RunRoute() {
  const { runId = '' } = useParams()
  const nav = useNavigate()
  return (
    <RunScreen
      runId={runId}
      onOpenReport={(id) => nav(paths.report(id))}
      onOpenWorkflow={(id) => nav(paths.workflow(id))}
    />
  )
}

function ReportRoute() {
  const { runId = '' } = useParams()
  return <ReportScreen runId={runId} />
}

function HistoryRoute() {
  const [sp] = useSearchParams()
  const nav = useNavigate()
  return (
    <HistoryScreen
      workflowId={sp.get('workflowId') ?? undefined}
      onOpenRun={(id) => nav(paths.run(id))}
      onOpenReport={(id) => nav(paths.report(id))}
    />
  )
}

function TemplatesRoute() {
  const nav = useNavigate()
  return <TemplatesScreen onOpenWorkflow={(id) => nav(paths.workflow(id))} />
}

function CiRoute() {
  const [sp] = useSearchParams()
  return (
    <CiScreen
      key={sp.toString()}
      initialKind={sp.get('kind') === 'gitlab' ? 'gitlab' : 'github'}
      initialWorkflowId={sp.get('workflowId') ?? undefined}
    />
  )
}
