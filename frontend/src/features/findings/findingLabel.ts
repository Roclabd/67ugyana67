import type { Finding } from '../../api/types'

/** Короткая подпись находки: класс для SECRET/SAST, координаты и advisory для SCA. */
export function findingLabel(f: Finding): string {
  if (f.category === 'SCA') return `${f.artifact ?? '?'} ${f.version ?? ''} · ${f.advisoryId ?? ''}`.trim()
  return f.class ?? f.rule
}
