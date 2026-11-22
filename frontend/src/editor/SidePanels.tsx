/** Блоки боковой панели редактора: замена ноды и редактирование связи. */
import { useState } from 'react'
import type { Edge } from '@xyflow/react'
import type { NodeDefinition } from '../api/types'
import type { PortChoice } from './graph'
import { t } from '../i18n'
import { defTitle } from '../i18n/nodes'

export function ReplaceNode({ choices, disabled, onReplace }: {
  choices: NodeDefinition[]
  disabled: boolean
  onReplace: (def: NodeDefinition) => void
}) {
  const [open, setOpen] = useState(false)
  const [type, setType] = useState('')
  const replacement = choices.find((def) => def.type === type)
  if (choices.length === 0) {
    return <button type="button" className="btn" disabled title={t('ed.noReplace')}>{t('ed.replace')}</button>
  }
  if (!open) {
    return <button type="button" className="btn" disabled={disabled} onClick={() => setOpen(true)}>{t('ed.replaceDots')}</button>
  }
  return (
    <div className="editor__replace-fields">
      <label className="field">
        <span>{t('ed.replaceWith')}</span>
        <select className="select" value={replacement?.type ?? ''} disabled={disabled} onChange={(e) => setType(e.target.value)}>
          <option value="">{t('ed.pickStage')}</option>
          {choices.map((def) => <option key={def.type} value={def.type}>{defTitle(def)}</option>)}
        </select>
      </label>
      <p className="muted">{t('ed.replaceNote')}</p>
      <div className="row">
        <button
          type="button"
          className="btn btn--primary"
          disabled={disabled || !replacement}
          onClick={() => {
            if (!replacement) return
            onReplace(replacement)
            setOpen(false)
            setType('')
          }}
        >
          {t('ed.replace')}
        </button>
        <button type="button" className="btn" onClick={() => setOpen(false)}>{t('np.cancel')}</button>
      </div>
    </div>
  )
}

/** Выбранная связь: откуда и куда, удаление и переподключение к другому совместимому порту. */
export function EdgePanel({ edge, sourceTitle, targetTitle, nodeTitle, choicesFor, onDelete, onReconnect }: {
  edge: Edge
  sourceTitle: string
  targetTitle: string
  nodeTitle: (nodeId: string) => string
  choicesFor: (side: 'target' | 'source') => PortChoice[]
  onDelete: () => void
  onReconnect: (side: 'target' | 'source', choice: PortChoice) => void
}) {
  const [side, setSide] = useState<'target' | 'source' | null>(null)
  const [picked, setPicked] = useState('')
  const choices = side ? choicesFor(side) : []
  const key = (c: PortChoice) => `${c.nodeId}\u0000${c.port}`
  const choice = choices.find((c) => key(c) === picked)

  function cancel() {
    setSide(null)
    setPicked('')
  }

  return (
    <div className="stack" data-testid="edge-panel">
      <div className="card__title" style={{ margin: 0 }}>{t('ed.link')}</div>
      <div className="editor__edge-ends">
        <div>{t('ed.source')}: <strong>{sourceTitle}</strong> · {t('ed.port')} <span className="mono">{edge.sourceHandle}</span></div>
        <div className="editor__edge-arrow" aria-hidden="true">↓</div>
        <div>{t('ed.target')}: <strong>{targetTitle}</strong> · {t('ed.port')} <span className="mono">{edge.targetHandle}</span></div>
      </div>
      {!side && (
        <div className="editor__actions">
          <button type="button" className="btn" onClick={() => setSide('target')}>{t('ed.reconnect')}</button>
          <button type="button" className="btn btn--danger" onClick={onDelete}>{t('ed.deleteLink')}</button>
        </div>
      )}
      {side && (
        <div className="editor__replace-fields">
          <div className="row editor__sides">
            <button type="button" className={`btn${side === 'target' ? ' btn--on' : ''}`} onClick={() => { setSide('target'); setPicked('') }}>{t('ed.otherTarget')}</button>
            <button type="button" className={`btn${side === 'source' ? ' btn--on' : ''}`} onClick={() => { setSide('source'); setPicked('') }}>{t('ed.otherSource')}</button>
          </div>
          {choices.length === 0 ? (
            <p className="muted">{t('ed.noPorts')}</p>
          ) : (
            <label className="field">
              <span>{side === 'target' ? t('ed.newTarget') : t('ed.newSource')} {t('ed.onlyCompat')}</span>
              <select className="select" value={picked} onChange={(e) => setPicked(e.target.value)}>
                <option value="">{t('ed.pickPort')}</option>
                {choices.map((c) => (
                  <option key={key(c)} value={key(c)}>{nodeTitle(c.nodeId)} · {t('ed.port')} {c.port} ({c.type})</option>
                ))}
              </select>
            </label>
          )}
          <div className="row">
            <button type="button" className="btn btn--primary" disabled={!choice} onClick={() => choice && onReconnect(side, choice)}>{t('ed.apply')}</button>
            <button type="button" className="btn" onClick={cancel}>{t('np.cancel')}</button>
          </div>
        </div>
      )}
    </div>
  )
}
