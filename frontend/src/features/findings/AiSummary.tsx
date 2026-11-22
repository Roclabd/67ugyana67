/**
 * Раздел `ai` отчёта: резюме, порядок исправления, группы связанных находок и счётчики валидатора.
 * Ссылки на находки в priorities/groups уже проверены валидатором (только id из входа) — здесь лишь подписи к ним.
 */
import type { Finding, ReportAi } from '../../api/types'
import { Card } from '../../ui'
import { formatLocation } from '../../ui/format'
import { findingLabel } from './findingLabel'
import { t } from '../../i18n'

export function AiSummary({ ai, findings }: { ai: ReportAi; findings: Finding[] }) {
  const byId = new Map(findings.map((f) => [f.id, f]))
  // Человеческое название и файл без папок: полный путь — в подсказке, чтобы список читался, а не тонул в путях.
  const label = (id: string) => {
    const f = byId.get(id)
    return f ? `${f.title ?? findingLabel(f)} · ${formatLocation(f.path.split('/').pop() ?? f.path, f.line)}` : id
  }
  const fullPath = (id: string) => {
    const f = byId.get(id)
    return f ? formatLocation(f.path, f.line) : undefined
  }
  const v = ai.validator
  return (
    <Card title={t('ai.title')}>
      <div className="stack">
        <div className="row">
          <span className={`badge badge--${ai.status === 'OK' ? 'SUCCESS' : ai.status === 'PARTIAL' ? 'PARTIAL' : 'neutral'}`}>
            {ai.status === 'OK' ? t('ai.ok') : ai.status === 'PARTIAL' ? t('ai.part') : t('ai.none')}
          </span>
          {(ai.model || ai.provider) && <span className="muted">{[ai.model, ai.provider].filter(Boolean).join(' · ')}</span>}
        </div>
        {ai.status === 'NOT_RECEIVED' && (
          <div className="alert alert--info">
            {ai.reason ?? t('ai.unavailable')} {t('ai.shown')}
          </div>
        )}
        {ai.summary && <p className="finding__text">{ai.summary}</p>}
        {ai.priorities && ai.priorities.length > 0 && (
          <div>
            <div className="finding__label">{t('ai.order')}</div>
            <ol className="finding__steps">{ai.priorities.map((id) => <li key={id} title={fullPath(id)}>{label(id)}</li>)}</ol>
          </div>
        )}
        {ai.groups && ai.groups.length > 0 && (
          <div>
            <div className="finding__label">{t('ai.groups')}</div>
            <div className="stack">
              {ai.groups.map((g, i) => (
                <div key={i} className="finding__ai">
                  <strong>{g.title}</strong>
                  <p className="finding__text">{g.story}</p>
                  <div className="muted">{g.findingIds.map(label).join(' + ')}</div>
                </div>
              ))}
            </div>
          </div>
        )}
        {v && (
          <div className="muted">
            {t('ai.vHead', { r: v.responses, s: v.schemaFailures })}
            {v.retries !== undefined ? t('ai.vRetries', { n: v.retries }) : ''}{t('ai.vCve', { n: v.rejectedCves })}
            {v.rejectedLocations !== undefined ? t('ai.vLoc', { n: v.rejectedLocations }) : ''}{t('ai.vRefs', { n: v.rejectedFindingRefs })}
            {v.rejectedDisputes ? t('ai.vDisp', { n: v.rejectedDisputes }) : ''}.
          </div>
        )}
      </div>
    </Card>
  )
}
