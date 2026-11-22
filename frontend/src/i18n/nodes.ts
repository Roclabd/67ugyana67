import type { NodeDefinition } from '../api/types'
import { tOr } from './index'

/**
 * Название ноды: сервер присылает его по-русски, на английском берётся перевод по типу ноды
 * (ключ `node.<type>`). Если определения нет (неизвестный тип) — показывается запасной текст.
 */
export function defTitle(def: Pick<NodeDefinition, 'type' | 'title'> | undefined, fallback = ''): string {
  return def ? tOr('node.' + def.type, def.title) : fallback
}
