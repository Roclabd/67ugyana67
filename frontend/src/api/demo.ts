import { useEffect, useState } from 'react'
import { api } from './client'

let cached: boolean | undefined
let pending: Promise<boolean> | undefined

/** Публичный демо-режим сервера (GET /api/meta). Ошибка или старый сервер = обычный режим. */
function loadDemo(): Promise<boolean> {
  pending ??= api.getMeta().then(
    (meta) => (cached = meta.publicDemo === true),
    () => (cached = false),
  )
  return pending
}

export function useDemo(): boolean {
  const [demo, setDemo] = useState(cached ?? false)
  useEffect(() => {
    let alive = true
    void loadDemo().then((value) => alive && setDemo(value))
    return () => {
      alive = false
    }
  }, [])
  return demo
}
