import { Handle, Position, type NodeProps } from '@xyflow/react'
import { useCatalog } from '../store'
import { CircleAlert, CirclePause, Link2Off } from 'lucide-react'
import { StatusBadge } from '../ui'
import { isPrimaryFailure, nodeReason } from '../run/problems'
import type { FlowNode } from './graph'
import { nodeBadgeText, nodeFindings } from '../features/findings/nodeFindings'
import { t } from '../i18n'
import { defTitle } from '../i18n/nodes'

const CATEGORY_COLOR: Record<string, string> = {
  TRIGGER: '#6b4fbb',
  SOURCE: '#2f6f9f',
  ANALYZER: '#0a7a3e',
  LOGIC: '#8a6d00',
  AI: '#b04a8a',
  OUTPUT: '#c2410c',
}

/** Нода на холсте: заголовок, порты (handle id = имя порта), живой статус из SSE. */
export function StepNode({ data, selected }: NodeProps<FlowNode>) {
  const def = useCatalog((s) => s.byType[data.nodeType])
  const { live, invalidPorts } = data
  const reason = live ? nodeReason(live, def?.category === 'AI') : null
  const primary = !!live && !data.nodeType.startsWith('notify.') && isPrimaryFailure(live)
  const skipReason = live?.status === 'SKIPPED' ? live.skipCause?.reason : undefined
  const blocked = skipReason === 'UPSTREAM_FAILURE'
  const stopped = skipReason === 'RUN_STOPPED'
  const badge = def?.category === 'ANALYZER' && live && live.status !== 'RUNNING' ? nodeBadgeText(nodeFindings(live.output)) : null
  const color = def ? CATEGORY_COLOR[def.category] : '#b3261e'
  const title = def ? defTitle(def) : t('ed.unknownNode', { type: data.nodeType })

  return (
    <div
      className={`step-node ${selected ? 'step-node--selected' : ''} ${live ? `step-node--${live.status}` : ''} ${primary ? 'step-node--primary-failure' : ''} ${skipReason ? `step-node--${skipReason}` : ''}`}
      style={{ borderTopColor: color }}
    >
      <div className="step-node__title" title={title}>{title}</div>
      <div className="step-node__type mono" title={data.nodeType}>{data.nodeType}</div>
      {def && (def.inputs.length > 0 || def.outputs.length > 0) && (
        <div className="step-node__ports">
          <div>
            {def.inputs.map((p) => (
              <div className="step-node__port-row" key={p.name}>
                <Handle id={p.name} type="target" position={Position.Left} className={invalidPorts?.includes(p.name) ? 'handle--invalid' : undefined} title={`${p.name}: ${p.type}${p.required ? ' (' + t('ed.required') + ')' : ''}`} />
                <span className="step-node__port" title={p.name}>{p.name}</span>
              </div>
            ))}
          </div>
          <div className="step-node__outputs">
            {def.outputs.map((p) => (
              <div className="step-node__port-row" key={p.name}>
                <Handle id={p.name} type="source" position={Position.Right} title={`${p.name}: ${p.type}`} />
                <span className="step-node__port" title={p.name}>{p.name}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {live && (
        <div className="step-node__status">
          {primary && <span className="step-node__root"><CircleAlert size={13} aria-hidden="true" /> {t('prob.primary')}</span>}
          {blocked && <span className="step-node__impact"><Link2Off size={13} aria-hidden="true" /> {t('ed.blocked')}</span>}
          {stopped && <span className="step-node__impact"><CirclePause size={13} aria-hidden="true" /> {t('ed.stopped')}</span>}
          {!primary && !blocked && !stopped && <StatusBadge status={live.status} />}
        </div>
      )}
      {badge && (
        <div className="step-node__findings" title={t('nf.found')}>{badge}</div>
      )}
      {live && reason && (
        <div className={`step-node__reason step-node__reason--${live.status}`} title={reason}>{reason}</div>
      )}
      {live?.status === 'RUNNING' && live.progress && (
        <div className="step-node__progress" title={live.progress.note ?? undefined}>
          <span style={{ width: `${live.progress.percent}%` }} />
        </div>
      )}
    </div>
  )
}
