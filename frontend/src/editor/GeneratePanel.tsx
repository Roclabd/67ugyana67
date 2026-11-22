/**
 * «Сценарий из текста» (звёздочка 3): описание словами → POST /api/workflows/generate → черновик на холсте.
 * Граф собирает LLM, проверяет сервер (GraphValidator); фронт ничего не разрешает сам —
 * черновик сохраняется и запускается только через обычные «Сохранить»/«Запустить», которые снова проходят проверку.
 */
import { useState } from 'react'
import { api } from '../api/client'
import { ApiError, errorMessage } from '../api/errors'
import type { GraphError, WorkflowDraft } from '../api/types'
import { t } from '../i18n'

const MAX_LENGTH = 4000

const examples = () => [
  t('gen.ex1'),
  t('gen.ex2'),
  t('gen.ex3'),
]

export interface GeneratePanelProps {
  /** На холсте уже есть ноды — черновик их заменит. */
  hasGraph: boolean
  onGenerated: (draft: WorkflowDraft) => void
  onErrors: (errors: GraphError[]) => void
  onClose: () => void
}

export function GeneratePanel({ hasGraph, onGenerated, onErrors, onClose }: GeneratePanelProps) {
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function generate() {
    setBusy(true)
    setError(null)
    onErrors([])
    try {
      const res = await api.generateWorkflow(text.trim())
      if (!res.workflow || res.errors.length) {
        onErrors(res.errors)
        setError(t('gen.badGraph'))
        return
      }
      onGenerated(res.workflow)
    } catch (err) {
      if (err instanceof ApiError && err.graphErrors.length) onErrors(err.graphErrors)
      setError(err instanceof ApiError && err.status === 503 ? t('gen.unavailable', { msg: err.message }) : errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const tooLong = text.length > MAX_LENGTH
  return (
    <div className="generate">
      <div className="row">
        <strong>{t('gen.title')}</strong>
        <span className="muted">{t('gen.sub')}</span>
        <span className="spacer" />
        <button className="btn" onClick={onClose}>{t('gen.hide')}</button>
      </div>
      <textarea
        className="textarea"
        rows={3}
        placeholder={t('gen.ph')}
        value={text}
        disabled={busy}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && text.trim() && !tooLong && !busy) void generate()
        }}
      />
      <div className="generate__examples">
        {examples().map((ex) => (
          <button key={ex} className="btn generate__example" disabled={busy} onClick={() => setText(ex)}>{ex}</button>
        ))}
      </div>
      <div className="row">
        <button className="btn btn--primary" disabled={busy || !text.trim() || tooLong} onClick={() => void generate()}>
          {busy ? t('gen.building') : hasGraph ? t('gen.replaceGraph') : t('gen.build')}
        </button>
        <span className={tooLong ? 'alert--error' : 'muted'}>{text.length} / {MAX_LENGTH}</span>
        {hasGraph && !busy && <span className="muted">{t('gen.replaceNote')}</span>}
        {busy && <span className="muted">{t('gen.eta')}</span>}
      </div>
      {error && <div className="alert alert--error">{error}</div>}
    </div>
  )
}
