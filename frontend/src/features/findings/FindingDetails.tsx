/**
 * Подробности находки (киллер-фича 4 — цепочка доказательства): по каким местам в коде анализатор пришёл к выводу,
 * и объяснение LLM — только прошедшее валидатор. Компонент общий: экран запуска и экран отчёта (A-2) берут его отсюда.
 * Значения секретов сюда не попадают: в находке только маска.
 */
import type { Finding, FindingAi, Location } from '../../api/types'
import { SecretMask } from '../../ui'
import { formatLocation } from '../../ui/format'
import { t } from '../../i18n'

/** Подписи проверок полезности рекомендаций (backend/ai, usefulness). */
const CHECK_LABEL: Record<string, string> = {
  get hasFixExample() { return t('chk.hasFixExample') },
  get fixParses() { return t('chk.fixParses') },
  get sameIdentifier() { return t('chk.sameIdentifier') },
  get fixPattern() { return t('chk.fixPattern') },
  get rerunClean() { return t('chk.rerunClean') },
  get targetSafe() { return t('chk.targetSafe') },
  get fromFixedVersions() { return t('chk.fromFixedVersions') },
}

export function FindingDetails({ finding: f }: { finding: Finding }) {
  return (
    <div className="stack finding">
      {f.description && <p className="finding__text">{f.description}</p>}
      {f.category === 'SECRET' && (
        <div className="row">
          <span className="muted">{t('fd.value')}</span> <SecretMask value={f.secretMasked} />
          <span className="muted">{t('fd.hidden')}</span>
        </div>
      )}
      {f.category === 'SCA' && (
        <div className="row mono">
          {f.group}:{f.artifact}:{f.version}
          {f.advisoryId && <span className="badge badge--neutral">{f.advisoryId}</span>}
          {f.fixedVersions?.length ? <span className="muted">{t('fd.fixedIn')} {f.fixedVersions.join(', ')}</span> : null}
        </div>
      )}
      <EvidenceChain evidence={f.evidence} />
      {f.remediation && (
        <div>
          <div className="finding__label">{t('fd.howFix')}</div>
          <p className="finding__text">{f.remediation}</p>
        </div>
      )}
      <AiBlock ai={f.ai} />
    </div>
  )
}

/** Цепочка доказательства: источник → преобразования → сток или правило. */
/** Для SQL-находок подписывает точки формирования и исполнения запроса, если они есть в заметках доказательства. */
function sqlStepLabel(evidence: Location[], note: string | undefined): string | null {
  if (!note || !evidence.some((e) => /^сток:.*SQL/i.test(e.note ?? ''))) return null
  if (/^сток:.*SQL/i.test(note)) return t('ev.sqlExec')
  if (/^(присваивание|дописывание)/i.test(note)) return t('ev.sqlBuilt')
  return null
}

export function EvidenceChain({ evidence }: { evidence: Location[] }) {
  if (evidence.length === 0) return null
  return (
    <div>
      <div className="finding__label">{t('fd.chain')}</div>
      <ol className="evidence">
        {evidence.map((e, i) => (
          <li key={i} className="evidence__step">
            <span className="mono evidence__loc">{formatLocation(e.path, e.line, e.endLine)}</span>
            {sqlStepLabel(evidence, e.note) && <strong className="evidence__tag">{sqlStepLabel(evidence, e.note)}</strong>}
            {e.note && <span className="evidence__note">{e.note}</span>}
          </li>
        ))}
      </ol>
    </div>
  )
}

/** Блок LLM. Нет объяснения — явная причина, а не пустое место: находку определил анализатор, не модель. */
export function AiBlock({ ai }: { ai?: FindingAi }) {
  if (!ai) return null
  if (ai.status !== 'OK') {
    const rejected = ai.status === 'REJECTED_BY_VALIDATOR'
    return (
      <div className={`alert ${rejected ? 'alert--warn' : 'alert--info'}`}>
        <div className="alert__title">{rejected ? t('fd.rejected') : t('fd.notReceived')}</div>
        {ai.reason && <div>{ai.reason}</div>}
        <div className="muted">{t('fd.stays')}</div>
        {ai.recommendedVersion && <div>{t('fd.updateTo')} {ai.recommendedVersion} {t('fd.perAdvisory')}</div>}
      </div>
    )
  }
  const checks = Object.entries(ai.usefulnessChecks ?? {})
  return (
    <div className="finding__ai">
      <div className="finding__label">{t('fd.llmOk')}</div>
      {ai.explanation && <p className="finding__text">{ai.explanation}</p>}
      {ai.impact && <p className="finding__text"><strong>{t('fd.impact')}</strong> {ai.impact}</p>}
      {ai.recommendedVersion && <p className="finding__text"><strong>{t('fd.target')}</strong> {ai.recommendedVersion} {t('fd.targetNote')}</p>}
      {ai.fixSteps && ai.fixSteps.length > 0 && (
        <ol className="finding__steps">{ai.fixSteps.map((s, i) => <li key={i}>{s}</li>)}</ol>
      )}
      {ai.fixExample && (
        <details>
          <summary>{t('fd.example')}</summary>
          <pre>{ai.fixExample}</pre>
        </details>
      )}
      {checks.length > 0 && (
        <div className="row finding__checks" title={t('fd.autoChecks')}>
          {checks.map(([k, ok]) => (
            <span key={k} className={`badge ${ok ? 'badge--SUCCESS' : 'badge--FAILED'}`}>
              {ok ? '✓' : '✗'} {CHECK_LABEL[k] ?? k}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
