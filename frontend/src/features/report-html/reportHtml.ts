/**
 * HTML-отчёт одним файлом: открывается без нашего сервера, печатается и сохраняется в PDF из браузера.
 * Строится из отчёта сервера как есть — находки, покрытие, проверенные правила, AI-сводка; секреты — только маской.
 */
import type { Finding, Report, Severity } from '../../api/types'
import { describeRules } from '../checks/catalog'
import { findingLabel } from '../findings/findingLabel'
import { isTestSecret } from '../findings/testSecrets'
import { SEVERITY_LABEL } from '../../ui/format'
import { BRAND } from '../../brand'

const ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const COLOR: Record<Severity, string> = { CRITICAL: '#b3261e', HIGH: '#d9531e', MEDIUM: '#c48a00', LOW: '#4a7bb7' }

export function esc(text: unknown): string {
  return String(text ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)
}

const loc = (path: string, line?: number, end?: number) => `${path}${line ? `:${line}${end && end !== line ? `–${end}` : ''}` : ''}`

function findingBlock(f: Finding): string {
  const ai = (f as Finding & { ai?: { status?: string; explanation?: string; fixSteps?: string[]; reason?: string } }).ai
  const evidence = f.evidence.map((e) => `<li><code>${esc(loc(e.path, e.line, e.endLine))}</code>${e.note ? ` — ${esc(e.note)}` : ''}</li>`).join('')
  return `<section class="finding">
  <div class="head"><span class="sev" style="background:${COLOR[f.severity]}">${esc(SEVERITY_LABEL[f.severity])}</span>
  <span class="cat">${esc(f.category)}</span> <strong>${esc(findingLabel(f))}</strong> ${esc(f.title ?? '')}</div>
  <div class="where"><code>${esc(loc(f.path, f.line, f.endLine))}</code>${f.secretMasked ? ` · секрет: <code>${esc(f.secretMasked)}</code>` : ''}</div>
  ${f.description ? `<p>${esc(f.description)}</p>` : ''}
  ${evidence ? `<div class="label">Цепочка доказательства</div><ol>${evidence}</ol>` : ''}
  ${f.remediation ? `<div class="label">Как исправить</div><p>${esc(f.remediation)}</p>` : ''}
  ${ai?.status === 'OK' && ai.explanation ? `<div class="label">Объяснение AI (прошло валидатор)</div><p>${esc(ai.explanation)}</p>${ai.fixSteps?.length ? `<ol>${ai.fixSteps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}` : ''}
</section>`
}

export function reportHtml(report: Report, meta: { workflowName?: string; finishedAt?: string } = {}): string {
  const findings = [...report.findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity))
  const counts = ORDER.map((s) => `<div class="stat"><b style="color:${COLOR[s]}">${findings.filter((f) => f.severity === s).length}</b>${esc(SEVERITY_LABEL[s])}</div>`).join('')
  const coverage = Object.entries(report.coverage.byAnalyzer).map(([id, c]) => `<tr><td>${esc(id)}</td><td>${esc(c.status)}</td><td>${c.filesAnalyzed}</td>
    <td>${describeRules(c.rulesApplied).map((r) => esc(r.title)).join(', ')}</td></tr>`).join('')
  const ai = report.ai
  const aiBlock = ai?.status === 'OK' || ai?.status === 'PARTIAL'
    ? `<h2>AI-сводка</h2><p class="muted">${esc(ai.provider ?? '')} · ${esc(ai.model ?? '')}</p>${ai.summary ? `<p>${esc(ai.summary)}</p>` : ''}
       ${(ai.groups ?? []).map((g) => `<div class="group"><strong>${esc(g.title)}</strong><p>${esc(g.story)}</p></div>`).join('')}`
    : `<h2>AI-сводка</h2><p class="muted">Объяснения не получены${ai?.reason ? `: ${esc(ai.reason)}` : ''}. Находки определены анализаторами и от этого не зависят.</p>`
  const analyzers = Object.entries(report.coverage.byAnalyzer)
  const gaps = analyzers.flatMap(([id, c]) => [...c.filesSkipped, ...c.unresolved]
    .map((x) => `<li><code>${esc(id)}</code> <code>${esc(loc(x.path, x.line))}</code> — ${esc(x.reason)}</li>`))
  const incomplete = report.coverage.status !== 'COMPLETE'
    ? `<div class="warn">Анализ выполнен частично — отсутствие находок не означает, что проблем нет.${gaps.length ? `<ul>${gaps.join('')}</ul>` : ''}</div>` : ''
  const testSecrets = analyzers.flatMap(([, c]) => c.dismissed.filter(isTestSecret))
  const attention = testSecrets.length
    ? `<h2>Обратите внимание: секреты в тестовом коде (${testSecrets.length})</h2>
       <p>Это не уязвимость приложения, но значения лежат в репозитории — лучше вынести их в переменные окружения тестов.</p>
       <ul>${testSecrets.map((d) => `<li><code>${esc(loc(d.path, d.line))}</code> · ${esc(d.rule.replace(/^secret\./, ''))}</li>`).join('')}</ul>`
    : ''
  return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Отчёт проверки ${esc(meta.workflowName ?? report.runId)}</title>
<style>
  body{font:14px/1.5 'Segoe UI',system-ui,sans-serif;color:#17201b;max-width:960px;margin:24px auto;padding:0 16px}
  h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid #d9e0dc;padding-bottom:4px}
  .muted{color:#5b6b62} code{font-family:Consolas,monospace;font-size:12px;background:#eef2f0;padding:1px 4px;border-radius:3px}
  .stats{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0} .stat{border:1px solid #d9e0dc;border-radius:8px;padding:8px 14px;min-width:90px}
  .stat b{display:block;font-size:22px} table{border-collapse:collapse;width:100%} td,th{border-bottom:1px solid #d9e0dc;padding:6px 8px;text-align:left;vertical-align:top}
  .finding{border:1px solid #d9e0dc;border-radius:8px;padding:10px 14px;margin:10px 0;break-inside:avoid}
  .sev{color:#fff;border-radius:4px;padding:1px 8px;font-size:12px;margin-right:6px} .cat{font-size:12px;color:#5b6b62;margin-right:6px}
  .where{margin:4px 0} .label{font-weight:600;margin-top:8px} .group{background:#f5f7f6;border-radius:8px;padding:8px 12px;margin:8px 0}
  .warn{background:#fff4e0;border:1px solid #e8c27a;border-radius:8px;padding:8px 12px;margin:12px 0}
  @media print{body{margin:0} .finding,.group{break-inside:avoid}}
</style></head><body>
<h1>Отчёт проверки безопасности</h1>
<p class="muted">${esc(meta.workflowName ?? '')} · запуск <code>${esc(report.runId)}</code>${meta.finishedAt ? ` · ${esc(meta.finishedAt)}` : ''}<br>
вход <code>${esc(report.inputHash)}</code> · правила <code>${esc(report.rulesVersion)}</code> · покрытие <b>${esc(report.coverage.status)}</b></p>
${incomplete}
<div class="stats"><div class="stat"><b>${findings.length}</b>Находок</div>${counts}</div>
${aiBlock}
<h2>Находки</h2>
${findings.length ? findings.map(findingBlock).join('\n') : '<p class="muted">Находок нет.</p>'}
${attention}
<h2>Что проверяли</h2>
<table><tr><th>Анализатор</th><th>Покрытие</th><th>Файлов</th><th>Правила</th></tr>${coverage}</table>
<p class="muted">${BRAND}. Значения секретов в отчёт не попадают — только маска.</p>
</body></html>
`
}
