import type { AnalyzerCoverage } from '../api/types'
import type { LiveNode } from '../store'
import { SeverityBadge, StatusBadge } from '../ui'
import { FindingDetails, findingLabel } from '../features/findings'
import { nodeFindings, sortBySeverity } from '../features/findings/nodeFindings'
import { formatLocation } from '../ui/format'
import { proofsFromOutput } from '../features/proofs/fromOutput'
import { ProofResults } from '../features/proofs/ProofResults'
import { qualityFromOutput } from '../features/quality/fromOutput'
import { QualityResults } from '../features/quality/QualityResults'
import { t } from '../i18n'

/**
 * Данные ноды в запуске: статус, ошибка, покрытие анализатора, вход/выход, логи.
 * Секреты в input/output уже замаскированы сервером — фронт их не раскрывает и не хранит.
 */
export function NodeRunPanel({ node }: { node: LiveNode }) {
  const proofs = proofsFromOutput(node.output)
  const quality = qualityFromOutput(node.output)
  return (
    <div className="stack">
      <div className="row">
        <strong>{t('nr.execution')}</strong>
        <StatusBadge status={node.status} />
        {node.durationMs !== undefined && <span className="muted">{node.durationMs} {t('nr.ms')}</span>}
      </div>
      {node.status === 'RUNNING' && node.progress && (
        <div className="muted">{node.progress.percent}%{node.progress.note ? ` · ${node.progress.note}` : ''}</div>
      )}
      {node.error && <div className="alert alert--error">{node.error}</div>}
      <FoundPanel output={node.output} />
      {proofs && <ProofResults report={proofs} />}
      {quality && <QualityResults quality={quality} />}
      {node.coverage && <CoveragePanel coverage={node.coverage} rulesVersion={node.rulesVersion} />}
      {node.input !== undefined && (
        <details>
          <summary>{t('nr.input')}</summary>
          <pre>{JSON.stringify(node.input, null, 2)}</pre>
        </details>
      )}
      {node.output !== undefined && (
        <details open>
          <summary>{t('nr.output')}</summary>
          <pre>{JSON.stringify(node.output, null, 2)}</pre>
        </details>
      )}
      {node.logs.length > 0 && (
        <details>
          <summary>{t('nr.logs')} ({node.logs.length})</summary>
          <pre>{node.logs.join('\n')}</pre>
        </details>
      )}
    </div>
  )
}

const FOUND_LIMIT = 10

/** «Что нашёл»: главные находки ноды (по серьёзности); каждая раскрывается в подробности. */
function FoundPanel({ output }: { output: unknown }) {
  const all = sortBySeverity(nodeFindings(output))
  if (all.length === 0) return null
  return (
    <div className="stack">
      <strong>{t('nf.found')} ({all.length})</strong>
      {all.slice(0, FOUND_LIMIT).map((f) => (
        <details key={f.id} className="finding-row">
          <summary className="row">
            <SeverityBadge severity={f.severity} />
            <span>{f.title ?? findingLabel(f)}</span>
            <span className="spacer" />
            <span className="mono muted">{formatLocation(f.path, f.line, f.endLine)}</span>
          </summary>
          <FindingDetails finding={f} />
        </details>
      ))}
      {all.length > FOUND_LIMIT && <span className="muted">{t('nf.more', { n: all.length - FOUND_LIMIT })}</span>}
    </div>
  )
}

/** Что анализатор проверил и что нет. «Находок нет» при PARTIAL/FAILED — не «чисто». */
function CoveragePanel({ coverage: c, rulesVersion }: { coverage: AnalyzerCoverage; rulesVersion?: string }) {
  const incomplete = c.status !== 'COMPLETE'
  return (
    <div className={`alert ${incomplete ? 'alert--warn' : 'alert--info'}`}>
      <div className="alert__title row">
        {t('cmp.coverage')} <StatusBadge status={c.status} />
      </div>
      <div>
        {t('nr.files', { a: c.filesAnalyzed, b: c.filesSkipped.length, c: c.rulesApplied.length })}
        {rulesVersion ? ` (${rulesVersion})` : ''}
      </div>
      {incomplete && <div>{t('nr.incomplete')}</div>}
      <CoverageList
        title={t('q.skipped')}
        items={c.filesSkipped.map((s) => `${formatLocation(s.path, s.line)} — ${s.reason}`)}
        open={c.filesSkipped.length > 0}
      />
      <CoverageList
        title={t('nr.unresolved')}
        items={c.unresolved.map((u) => `${formatLocation(u.path, u.line)} — ${u.reason}${u.subject ? ` (${u.subject})` : ''}`)}
        open={c.unresolved.length > 0}
      />
      <CoverageList
        title={t('safe.title.short')}
        items={c.dismissed.map((d) => `${formatLocation(d.path, d.line)} — ${d.reason}`)}
      />
    </div>
  )
}

function CoverageList({ title, items, open = false }: { title: string; items: string[]; open?: boolean }) {
  if (items.length === 0) return null
  return (
    <details open={open}>
      <summary>{title} ({items.length})</summary>
      <ul className="coverage-list">
        {items.map((t, i) => <li key={i}>{t}</li>)}
      </ul>
    </details>
  )
}
