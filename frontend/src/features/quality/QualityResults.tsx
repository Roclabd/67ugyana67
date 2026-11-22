/** Результат проверки качества кода: статус, счётчики по видам, список «файл:строка — сообщение». Безопасность не затрагивает. */
import { formatLocation } from '../../ui/format'
import { KIND_LABEL, STATUS_LABEL, type QualityBlock } from './fromOutput'
import { t } from '../../i18n'

export function QualityResults({ quality }: { quality: QualityBlock }) {
  const incomplete = quality.status === 'PARTIAL' || quality.status === 'TIMEOUT' || quality.status === 'ERROR'
  const files = Object.entries(quality.filesByLanguage).map(([l, n]) => `${l}: ${n}`).join(', ')
  return (
    <div className="stack">
      <div className="row">
        <strong>{t('q.title')} {STATUS_LABEL[quality.status]}</strong>
        <span className="muted">{t('q.files')} {quality.filesAnalyzed}{files ? ` (${files})` : ''}</span>
      </div>
      <div className={`alert ${incomplete ? 'alert--warn' : 'alert--info'}`}>{quality.message}</div>
      {quality.summary.total > 0 && (
        <div className="row">
          {Object.entries(KIND_LABEL).map(([kind, label]) => (
            <span key={kind} className="badge badge--neutral">{label}: {quality.summary.byKind[kind] ?? 0}</span>
          ))}
        </div>
      )}
      {quality.diagnostics.length > 0 && (
        <table className="table">
          <tbody>
            {quality.diagnostics.map((d, i) => (
              <tr key={i}>
                <td className="mono">{formatLocation(d.path, d.line)}</td>
                <td><span className="badge badge--neutral">{KIND_LABEL[d.kind]}</span>{d.confidence === 'LIKELY' && <div className="muted">{t('q.likely')}</div>}</td>
                <td>{d.message}<div className="muted mono">{d.rule}</div></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {quality.truncated && <div className="muted">{t('q.partial')}</div>}
      {quality.skipped.length > 0 && (
        <details>
          <summary>{t('q.skipped')} ({quality.skipped.length})</summary>
          <ul className="coverage-list">{quality.skipped.map((s, i) => <li key={i}>{s.path} — {s.reason}</li>)}</ul>
        </details>
      )}
      {quality.unsupported.length > 0 && <div className="muted">{t('q.unsupported')} {quality.unsupported.map((e) => `.${e}`).join(', ')}</div>}
    </div>
  )
}
