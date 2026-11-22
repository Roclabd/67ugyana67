import { t } from '../../i18n'
/**
 * «Что проверяли» — понятные названия и суть алгоритма для id правил из покрытия анализаторов (coverage.rulesApplied).
 * Если сервер прислал описание правила сам (coverage.rules), оно важнее каталога. Неизвестный id показывается как есть.
 */
export interface CheckInfo {
  title: string
  how: string
}

export const CHECKS: Record<string, CheckInfo> = {
  'secret.password': { get title() { return t('rule.secret.password.t') }, get how() { return t('rule.secret.password.h') } },
  'secret.api-key': { get title() { return t('rule.secret.api-key.t') }, get how() { return t('rule.secret.api-key.h') } },
  'secret.configuration-token': { get title() { return t('rule.secret.configuration-token.t') }, get how() { return t('rule.secret.configuration-token.h') } },
  'secret.secret-fallback': { get title() { return t('rule.secret.secret-fallback.t') }, get how() { return t('rule.secret.secret-fallback.h') } },
  'secret.recoverable-token': { get title() { return t('rule.secret.recoverable-token.t') }, get how() { return t('rule.secret.recoverable-token.h') } },
  'secret.high-entropy': { get title() { return t('rule.secret.high-entropy.t') }, get how() { return t('rule.secret.high-entropy.h') } },
  'secret.custom-regex': { get title() { return t('rule.secret.custom-regex.t') }, get how() { return t('rule.secret.custom-regex.h') } },
  'sca.maven-advisory': { get title() { return t('rule.sca.maven-advisory.t') }, get how() { return t('rule.sca.maven-advisory.h') } },
  'sast.sql.taint-to-query': { get title() { return t('rule.sast.sql.taint-to-query.t') }, get how() { return t('rule.sast.sql.taint-to-query.h') } },
  'sast.tls.trust-all': { get title() { return t('rule.sast.tls.trust-all.t') }, get how() { return t('rule.sast.tls.trust-all.h') } },
  'sast.cors.any-origin-with-credentials': { get title() { return t('rule.sast.cors.any-origin-with-credentials.t') }, get how() { return t('rule.sast.cors.any-origin-with-credentials.h') } },
  'sast.route.public-sensitive-route': { get title() { return t('rule.sast.route.public-sensitive-route.t') }, get how() { return t('rule.sast.route.public-sensitive-route.h') } },
  'sast.idor.read-by-id-without-owner': { get title() { return t('rule.sast.idor.read-by-id-without-owner.t') }, get how() { return t('rule.sast.idor.read-by-id-without-owner.h') } },
}

export interface CheckRow {
  id: string
  title: string
  how?: string
}

/** Правила анализатора для показа: описание сервера → каталог → id как есть. */
export function describeRules(ids: string[], server?: { id: string; title?: string; description?: string }[]): CheckRow[] {
  const fromServer = new Map((server ?? []).map((r) => [r.id, r]))
  return ids.map((id) => {
    const s = fromServer.get(id)
    const known = CHECKS[id]
    return {
      id,
      title: s?.title ?? known?.title ?? id,
      how: s?.description ?? known?.how,
    }
  })
}
