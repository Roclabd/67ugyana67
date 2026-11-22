/**
 * Общие компоненты интерфейса. Экраны A используют только их и классы из styles.css.
 */
import type { ReactNode } from 'react'
import { SEVERITIES } from '../api/types'
import type { ApiState } from '../api/useApi'
import type { CoverageStatus, NodeStatus, RunStatus, Severity, SeverityCounts } from '../api/types'
import { SEVERITY_LABEL, STATUS_LABEL } from './format'
import { t } from '../i18n'

// ───────────── Страница ─────────────

export function Page({ title, subtitle, actions, children }: {
  title: string
  subtitle?: ReactNode
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <div className="page">
      <div className="page__head">
        <h1 className="page__title">{title}</h1>
        {actions}
      </div>
      {subtitle && <p className="page__subtitle">{subtitle}</p>}
      {children}
    </div>
  )
}

export function Card({ title, children, actions }: { title?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <div className="row" style={{ marginBottom: 10 }}>
          {title && <h2 className="card__title" style={{ margin: 0 }}>{title}</h2>}
          <span className="spacer" />
          {actions}
        </div>
      )}
      {children}
    </section>
  )
}

// ───────────── Состояния загрузки ─────────────

export function Loading({ text }: { text?: string }) {
  return (
    <div className="state">
      <span className="spinner" /> {text ?? t('ui.loading')}
    </div>
  )
}

export function ErrorBox({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="alert alert--error row">
      <div>
        <div className="alert__title">{t('ui.error')}</div>
        {error}
      </div>
      <span className="spacer" />
      {onRetry && <button className="btn" onClick={onRetry}>{t('ui.retry')}</button>}
    </div>
  )
}

export function Empty({ text, children }: { text: string; children?: ReactNode }) {
  return (
    <div className="state">
      <div>{text}</div>
      {children}
    </div>
  )
}

/**
 * Показывает загрузку/ошибку сам, а данные отдаёт в children.
 *   <AsyncView state={runs.state} onRetry={runs.reload}>{(data) => …}</AsyncView>
 */
export function AsyncView<T>({ state, onRetry, children }: {
  state: ApiState<T>
  onRetry?: () => void
  children: (data: T) => ReactNode
}) {
  if (state.status === 'loading') return <Loading />
  if (state.status === 'error') return <ErrorBox error={state.error} onRetry={onRetry} />
  return <>{children(state.data)}</>
}

// ───────────── Бейджи ─────────────

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge badge--${severity}`}>{SEVERITY_LABEL[severity]}</span>
}

export function StatusBadge({ status }: { status: NodeStatus | RunStatus | CoverageStatus | null }) {
  if (!status) return <span className="badge badge--neutral">—</span>
  return <span className={`badge badge--${status}`}>{STATUS_LABEL[status]}</span>
}

/** Счётчики по критичности: «1 7 6 1». Нули показываются серым. labelled — с подписью («1 критичная»), где места хватает. */
export function SeverityCounts({ counts, labelled = false }: { counts: SeverityCounts; labelled?: boolean }) {
  return (
    <span className="counts" aria-label={SEVERITIES.map((s) => `${SEVERITY_LABEL[s]}: ${counts[s]}`).join(', ')}>
      {SEVERITIES.map((s) => (
        <span
          key={s}
          className={`badge ${counts[s] ? `badge--${s}` : 'badge--neutral'}`}
          title={SEVERITY_LABEL[s]}
        >
          {labelled ? `${counts[s]} ${SEVERITY_LABEL[s].toLowerCase()}` : counts[s]}
        </span>
      ))}
    </span>
  )
}

/** Маска секрета. Сырое значение на фронт не приходит никогда. */
export function SecretMask({ value }: { value?: string }) {
  return <span className="secret">{value ?? '••••'}</span>
}

// ───────────── Неполный анализ ─────────────

/**
 * Предупреждение о неполном анализе. Ставить над любыми результатами анализа:
 * при PARTIAL/FAILED «мало находок» не должно выглядеть как «всё чисто».
 */
export function CoverageBanner({ status, details }: { status: CoverageStatus | null; details?: ReactNode }) {
  if (status === 'COMPLETE') return null
  if (status === null) {
    return <div className="alert alert--info"><div className="alert__title">{t('cov.pending')}</div>{details}</div>
  }
  const failed = status === 'FAILED'
  return (
    <div className={`alert ${failed ? 'alert--error' : 'alert--warn'}`}>
      <div className="alert__title">
        {failed ? t('cov.failed') : t('cov.partial')} — {t('cov.warn')}
      </div>
      {details}
    </div>
  )
}
