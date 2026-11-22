import { useCallback, useEffect, useRef, useState } from 'react'
import { errorMessage } from './errors'

/** Состояние загрузки данных экрана. Экран обязан показать все три ветки. */
export type ApiState<T> =
  | { status: 'loading' }
  | { status: 'error'; error: string }
  | { status: 'ready'; data: T }

/**
 * Загрузка данных для экрана.
 *
 *   const runs = useApi(() => api.listRuns(), [])
 *   if (runs.state.status === 'loading') ...
 *
 * `deps` — когда перезагружать (как у useEffect). `reload()` — перезагрузить вручную.
 * Ответ устаревшего запроса отбрасывается, поэтому быстрые переключения не путают данные.
 */
export function useApi<T>(load: () => Promise<T>, deps: readonly unknown[]): { state: ApiState<T>; reload: () => void } {
  const [state, setState] = useState<ApiState<T>>({ status: 'loading' })
  const [tick, setTick] = useState(0)
  const loadRef = useRef(load)
  loadRef.current = load

  useEffect(() => {
    let alive = true
    setState({ status: 'loading' })
    loadRef.current().then(
      (data) => alive && setState({ status: 'ready', data }),
      (err: unknown) => alive && setState({ status: 'error', error: errorMessage(err) }),
    )
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- deps задаёт вызывающий
  }, [...deps, tick])

  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { state, reload }
}

/**
 * Действие с кнопкой (сохранить, скопировать, опубликовать). Результат и ошибку отдаёт сервер:
 * экран не решает сам, разрешено ли действие, а показывает ответ.
 */
export function useAction<A extends unknown[], R>(action: (...args: A) => Promise<R>) {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const actionRef = useRef(action)
  actionRef.current = action

  const run = useCallback(async (...args: A): Promise<R | undefined> => {
    setPending(true)
    setError(null)
    try {
      return await actionRef.current(...args)
    } catch (err) {
      setError(errorMessage(err))
      return undefined
    } finally {
      setPending(false)
    }
  }, [])

  return { run, pending, error }
}
