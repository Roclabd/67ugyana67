import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Check, CircleAlert, CodeXml, Box, KeyRound, TriangleAlert } from 'lucide-react'
import type { FindingCategory, RunStatus, Severity } from '../api/types'
import { severityNames } from './data'
import { t } from '../i18n'
export function Panel({
  title,
  action,
  children,
  className = '',
}: {
  title: string
  action?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={'surface ' + className}>
      <header className="surface-head">
        <h2>{title}</h2>
        {action}
      </header>
      {children}
    </section>
  )
}
export function Risk({ level }: { level: Severity }) {
  return (
    <span className={'pill risk-' + level}>
      <TriangleAlert size={13} />
      {severityNames[level]}
    </span>
  )
}
export function State({ value }: { value: RunStatus }) {
  const label = { SUCCESS: t('state.SUCCESS'), FAILED: t('state.FAILED'), PARTIAL: t('state.PARTIAL'), RUNNING: t('state.RUNNING') }
  return (
    <span className={'pill state-' + value}>
      {value === 'SUCCESS' ? <Check size={13} /> : value === 'FAILED' ? <CircleAlert size={13} /> : <i />}
      {label[value]}
    </span>
  )
}
export function Engine({ id }: { id: FindingCategory }) {
  const Icon = { SAST: CodeXml, SCA: Box, SECRET: KeyRound }[id]
  return <Icon size={18} />
}
export function Go({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link className="text-link" to={to}>
      {children}
    </Link>
  )
}
export function Heading({ title, sub, action }: { title: string; sub?: string; action?: ReactNode }) {
  return (
    <div className="heading">
      <div>
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
      {action}
    </div>
  )
}
