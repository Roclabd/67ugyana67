import type { ApiErrorBody, GraphError } from './types'

/** Ошибка API: HTTP-статус + тело {code, message, details}. Экран показывает message как есть. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details?: unknown

  constructor(status: number, body: ApiErrorBody) {
    super(body.message)
    this.name = 'ApiError'
    this.status = status
    this.code = body.code
    this.details = body.details
  }

  /** Ошибки графа из 422 (details.errors), если есть. */
  get graphErrors(): GraphError[] {
    const d = this.details as { errors?: GraphError[] } | undefined
    return Array.isArray(d?.errors) ? d.errors : []
  }
}

/** Текст ошибки для экрана: message ApiError или общий текст. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message
  if (err instanceof Error) return err.message
  return 'Неизвестная ошибка'
}
