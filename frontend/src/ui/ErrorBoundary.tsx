import { Component, type ReactNode } from 'react'
import { useLocation } from 'react-router-dom'

interface State { error: Error | null }

/** Ошибка одного экрана не должна гасить весь интерфейс: показываем причину и даём перезагрузить. */
class Boundary extends Component<{ children: ReactNode }, State> {
  override state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  override componentDidCatch(error: Error) {
    console.error('[ui] экран упал', error)
  }

  override render() {
    if (!this.state.error) return this.props.children
    return (
      <div role="alert" style={{ padding: 32, maxWidth: 640, margin: '64px auto', fontFamily: 'inherit' }}>
        <h2 style={{ margin: '0 0 12px' }}>Экран не открылся · This screen failed to load</h2>
        <p style={{ margin: '0 0 16px', opacity: 0.8 }}>
          Остальные разделы работают. Причина: {this.state.error.message || String(this.state.error)}
        </p>
        <div style={{ display: 'flex', gap: 12 }}>
          <button className="primary" type="button" onClick={() => window.location.reload()}>Перезагрузить</button>
          <a className="secondary" href="/">На обзор</a>
        </div>
      </div>
    )
  }
}

/** Сбрасывает ошибку при переходе на другой адрес. */
export function ErrorBoundary({ children }: { children: ReactNode }) {
  const { pathname } = useLocation()
  return <Boundary key={pathname}>{children}</Boundary>
}
