/**
 * Компактный список находок: строка — критичность, класс или координаты, место; по клику — подробности
 * с цепочкой доказательства и объяснением LLM. Порядок — как прислал сервер (стабильный, 5.8).
 */
import type { Finding } from '../../api/types'
import { SeverityBadge } from '../../ui'
import { formatLocation } from '../../ui/format'
import { FindingDetails } from './FindingDetails'
import { findingLabel } from './findingLabel'

export function FindingList({ findings }: { findings: Finding[] }) {
  return (
    <div className="stack">
      {findings.map((f) => (
        <details key={f.id} className="finding-row">
          <summary className="row">
            <SeverityBadge severity={f.severity} />
            <span className="badge badge--neutral">{f.category}</span>
            <strong>{findingLabel(f)}</strong>
            {f.title && <span>{f.title}</span>}
            <span className="spacer" />
            <span className="mono muted">{formatLocation(f.path, f.line, f.endLine)}</span>
          </summary>
          <FindingDetails finding={f} />
        </details>
      ))}
    </div>
  )
}
