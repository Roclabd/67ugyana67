import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, HashRouter } from 'react-router-dom'
import { App } from './App'
import { ErrorBoundary } from './ui/ErrorBoundary'
import './ui/styles.css'

import '@fontsource-variable/inter/wght.css'
import './workspace/navy.css'
const Router = import.meta.env.MODE === 'demo' ? HashRouter : BrowserRouter

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Router>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </Router>
  </StrictMode>,
)

import './workspace/steel.css'
