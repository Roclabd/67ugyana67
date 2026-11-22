import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload } from 'lucide-react'
import { api, errorMessage } from '../api/client'
import { useDemo } from '../api/demo'
import { t } from '../i18n'
import { createZipProject, uploadNewVersion, zipName, type Project } from './data'

const ZIP_FLOW = 'Проверить ZIP-архив'

/**
 * Один клик: выбрать ZIP → загрузка → запуск → экран запуска.
 * ZIP-проект: новая версия в тот же проект. Иначе: новый ZIP-проект с именем файла.
 * В демо-режиме проекты не создаются: используется общий сценарий проверки ZIP.
 */
export function ZipCheckButton({ project }: { project?: Project }) {
  const input = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  const demo = useDemo()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const version = project?.kind === 'archive'

  async function run(file: File) {
    setBusy(true)
    setError(undefined)
    try {
      let runId: string
      if (version && project) runId = await uploadNewVersion(project, file)
      else if (!demo) runId = await createZipProject(file, zipName(file.name))
      else {
        const { uploadId } = await api.upload(file)
        const flows = await api.listWorkflows()
        let id = flows.find((w) => w.name === ZIP_FLOW)?.id
        if (!id) id = (await api.copyTemplate('zip-scan', { name: ZIP_FLOW })).id
        runId = (await api.runWorkflow(id, { source: { kind: 'upload', uploadId } })).runId
      }
      navigate('/runs/' + runId)
    } catch (err) {
      setError(errorMessage(err))
      setBusy(false)
    }
  }

  return (
    <>
      <input
        ref={input}
        type="file"
        accept=".zip,application/zip"
        hidden
        onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) void run(f) }}
      />
      <button className="secondary" type="button" disabled={busy} onClick={() => input.current?.click()} title={error}>
        <Upload size={16} />
        {busy ? t('zip.uploading') : version ? t('zip.newVersion') : t('zip.check')}
      </button>
      {error && <span role="alert" style={{ color: 'var(--bad)', fontSize: 12 }}>{error}</span>}
    </>
  )
}
