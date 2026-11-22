import { useEffect, useRef, useState, type FormEvent } from 'react'
import { FolderPlus, X } from 'lucide-react'
import { errorMessage, USE_MOCKS } from '../api/client'
import { useNavigate } from 'react-router-dom'
import { addRepository, createZipProject, zipName, type Project } from './data'
import { t } from '../i18n'
import { useDemo } from '../api/demo'

export function NewProject({ close, created }: { close: () => void; created: (project: Project) => void }) {
  const dialog = useRef<HTMLDialogElement>(null)
  const saving = useRef(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const demo = useDemo()
  const navigate = useNavigate()
  const [tab, setTab] = useState<'repo' | 'zip'>('repo')
  const [zipFile, setZipFile] = useState<File>()
  const [zipTitle, setZipTitle] = useState('')

  useEffect(() => {
    const element = dialog.current!
    element.showModal()
    return () => element.close()
  }, [])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (saving.current) return
    const repo = String(new FormData(event.currentTarget).get('repository') ?? '')
    if (tab === 'zip' && !zipFile) { setError(t('np.zipPick')); return }
    saving.current = true
    setPending(true)
    setError('')
    try {
      if (tab === 'zip' && zipFile) {
        const runId = await createZipProject(zipFile, zipTitle)
        close()
        navigate('/runs/' + runId)
        return
      }
      created(await addRepository(repo))
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      saving.current = false
      setPending(false)
    }
  }

  return (
    <dialog ref={dialog} className="overlay project-dialog" aria-labelledby="project-form-title"
      onCancel={(event) => { event.preventDefault(); if (!saving.current) close() }}>
      <div className="dialog-head">
        <h2 id="project-form-title">{t('np.title')}</h2>
        <button type="button" className="icon-btn" aria-label={t('np.closeForm')} disabled={pending} onClick={close}><X size={18} /></button>
      </div>
      <div role="tablist" className="project-form-actions" style={{ justifyContent: 'flex-start', marginBottom: 12 }}>
        {(['repo', 'zip'] as const).map((id) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id} disabled={pending}
            className={tab === id ? 'primary' : 'secondary'} onClick={() => { setTab(id); setError('') }}>
            {id === 'repo' ? t('np.tabRepo') : t('np.tabZip')}
          </button>
        ))}
      </div>
      <form onSubmit={(event) => void submit(event)}>
        {tab === 'repo' ? (
          <>
            <label className="field">{t('np.url')}
              <input className="input" name="repository" type="url" placeholder="https://github.com/team/project"
                maxLength={200} autoComplete="off" required autoFocus disabled={pending} />
            </label>
            <p>{USE_MOCKS ? t('np.demoNote') : t('np.note')}</p>
          </>
        ) : (
          <>
            <label className="field">{t('np.zipFile')}
              <input className="input" type="file" accept=".zip,application/zip" required disabled={pending}
                onChange={(e) => {
                  const f = e.target.files?.[0]
                  setZipFile(f)
                  if (f && !zipTitle) setZipTitle(zipName(f.name))
                }} />
            </label>
            <label className="field">{t('np.zipName')}
              <input className="input" value={zipTitle} maxLength={80} autoComplete="off" required disabled={pending}
                onChange={(e) => setZipTitle(e.target.value)} />
            </label>
            <p>{t('np.zipNote')}</p>
          </>
        )}
        {error && <div role="alert" className="alert alert--error">{error}</div>}
        <div className="project-form-actions">
          <button type="button" className="secondary" disabled={pending} onClick={close}>{t('np.cancel')}</button>
          <button className="primary" type="submit" disabled={pending || demo} title={demo ? t('demo.readonly') : undefined}><FolderPlus size={16} />{pending ? t('np.saving') : t('proj.add')}</button>
        </div>
      </form>
    </dialog>
  )
}
