/** Результат тестов-доказательств: воспроизводится ли уязвимость на собранном приложении (D5). */
import type { ProofReport, ProofStatus } from './fromOutput'
import { t } from '../../i18n'

const LABEL: Record<ProofStatus, string> = {
  get REPRODUCED() { return t('proof.status.REPRODUCED') },
  get NOT_REPRODUCED() { return t('proof.status.NOT_REPRODUCED') },
  get NOT_SUPPORTED() { return t('proof.status.NOT_SUPPORTED') },
  get ERROR() { return t('proof.status.ERROR') },
  get TIMEOUT() { return t('proof.status.TIMEOUT') },
}

const BADGE: Record<ProofStatus, string> = {
  REPRODUCED: 'badge--HIGH',
  NOT_REPRODUCED: 'badge--SUCCESS',
  NOT_SUPPORTED: 'badge--neutral',
  ERROR: 'badge--FAILED',
  TIMEOUT: 'badge--PARTIAL',
}

export function ProofResults({ report }: { report: ProofReport }) {
  const reproduced = report.rows.filter((r) => r.status === 'REPRODUCED').length
  return (
    <div className="stack">
      <div className="row">
        <strong>{t('proof.title', { a: reproduced, b: report.rows.length })}</strong>
        {report.projectHash && <span className="muted mono" title={report.projectHash}>{t('proof.project')} {report.projectHash.slice(0, 12)}…</span>}
      </div>
      {report.error && <div className="alert alert--warn">{report.error}</div>}
      <table className="table">
        <tbody>
          {report.rows.map((r, i) => (
            <tr key={i}>
              <td className="mono">{r.sastClass}<div className="muted">{r.findingId}</div></td>
              <td><span className={`badge ${BADGE[r.status]}`}>{LABEL[r.status]}</span></td>
              <td>
                {r.details && <div className="muted">{r.details}</div>}
                {r.source && (
                  <details>
                    <summary>{t('proof.test')} {r.test}</summary>
                    <pre className="mono">{r.source}</pre>
                  </details>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
