import { Fragment, useState } from 'react'
import { api, errorMessage } from '../api/client'
import type { NodeDefinition, ParamSchema, TelegramAttachmentFormat } from '../api/types'
import { SECRET_MASK, TELEGRAM_CHAT_LIST_MAX_LENGTH } from '../api/types'
import { t, tOr } from '../i18n'
import { AttachmentChecks } from '../workspace/AttachmentChecks'

/**
 * Форма параметров ноды, построенная по JSON-схеме из GET /api/nodes.
 * Секретные параметры (secretParams) — поле пароля; сервер присылает маску «••••»,
 * а отправка маски обратно означает «не менять». Значение секрета на фронте не хранится.
 */
/** Подписи для параметров, у которых в схеме нет title (схемы нод задаёт сервер). Ключ — «тип.параметр» или имя параметра. */
const PARAM_LABELS: Record<string, string> = {
  'analyzer.sca.custom.coordinate': 'Зависимость (group:artifact)',
  'analyzer.sca.custom.lowerVersion': 'Запрещённые версии от',
  'analyzer.sca.custom.lowerInclusive': 'Включить начальную версию в диапазон',
  'analyzer.sca.custom.upperVersion': 'Запрещённые версии до',
  'analyzer.sca.custom.upperInclusive': 'Включить конечную версию в диапазон',
  'analyzer.sca.custom.severity': 'Критичность находки',
  token: 'Токен',
  'notify.webhook.url': 'Адрес вебхука (HTTPS)',
  'notify.webhook.token': 'Токен (Bearer)',
  'notify.smtp.to': 'Получатель',
  'source.repo.url': 'Адрес репозитория',
  'source.archive.uploadId': 'ID загруженного архива',
  'trigger.cron.cron': 'Расписание (cron, с секундами)',
  'trigger.cron.zone': 'Часовой пояс',
  'analyzer.secret.minSeverity': 'Минимальная критичность',
  'analyzer.secret.regex.pattern': 'Регулярное выражение',
  'logic.regex.pattern': 'Регулярное выражение',
  'logic.regex.text': 'Текст (иначе — вход)',
  'logic.compare.left': 'Левое значение (иначе — вход)',
  'logic.compare.right': 'Правое значение',
  'logic.compare.operator': 'Сравнение',
  'logic.filter.severity': 'Критичность',
  'approval.wait.fingerprint': 'Отпечаток находки (иначе — первая)',
  'approval.wait.timeoutSeconds': 'Сколько ждать решения, с',
}

/** Подпись параметра из клиентского словаря; на английском — перевод. */
const label = (k: string) => (PARAM_LABELS[k] === undefined ? undefined : tOr('param.' + k, PARAM_LABELS[k]))

export function ParamsForm({ def, params, onChange }: {
  def: NodeDefinition
  params: Record<string, unknown>
  onChange: (next: Record<string, unknown>) => void
}) {
  const telegram = def.type === 'notify.telegram'
  // Устаревший одиночный «format» в форме не показываем: его заменяет список «attachments».
  const props = Object.entries(def.paramsSchema.properties ?? {}).filter(([key]) => !(telegram && key === 'format'))
  if (props.length === 0) return <p className="muted">{t('pf.none')}</p>
  const required = new Set(def.paramsSchema.required ?? [])
  const set = (k: string, v: unknown) => {
    const next = { ...params, [k]: v }
    if (telegram && (v === undefined || v === '')) delete next[k]
    // Другой репозиторий — другие ветка, коммит и папка проекта: старые значения не переносим.
    if (def.type === 'source.repo' && k === 'url' && v !== params.url) {
      delete next.subdir
      delete next.branch
      delete next.commitSha
    }
    onChange(next)
  }

  return (
    <div className="stack">
      {props.map(([key, schema]) => {
        const display = telegram ? t('param.notify.telegram.' + key) : label(`${def.type}.${key}`)
        const hint = telegram ? telegramHint(key) : schema.description
        if (telegram && key === 'attachments') {
          const legacy = params.format
          const current = Array.isArray(params.attachments)
            ? (params.attachments as TelegramAttachmentFormat[])
            : legacy === 'none' ? [] : typeof legacy === 'string' ? [legacy as TelegramAttachmentFormat] : undefined
          return (
            <div className="field" key={key}>
              <span className="field__label">{display}</span>
              <AttachmentChecks
                value={current ?? []}
                onChange={(next) => onChange({ ...Object.fromEntries(Object.entries(params).filter(([k]) => k !== 'format')), attachments: next })}
              />
              <span className="field__hint">{current === undefined ? t('tg.inheritFormat') : t('tg.attachmentsHint')}</span>
              {current !== undefined && (
                <button
                  className="btn btn--ghost"
                  type="button"
                  onClick={() => onChange(Object.fromEntries(Object.entries(params).filter(([k]) => k !== 'format' && k !== 'attachments')))}
                >
                  {t('tg.inheritFormat')}
                </button>
              )}
            </div>
          )
        }
        return (
          <Fragment key={key}>
            <label className="field">
              <span className="field__label">
                {display ?? schema.title ?? label(key) ?? key}
                {required.has(key) && ' *'}
              </span>
              {def.type === 'source.archive' && key === 'uploadId' ? (
                <ArchiveUpload value={params[key]} onChange={(v) => set(key, v)} />
              ) : telegram && key === 'chatId' ? (
                <textarea
                  className="input"
                  rows={3}
                  maxLength={schema.maxLength ?? TELEGRAM_CHAT_LIST_MAX_LENGTH}
                  value={String(params[key] ?? '')}
                  onChange={(event) => set(key, event.target.value)}
                />
              ) : (
                <Field
                  schema={schema}
                  secret={def.secretParams.includes(key)}
                  value={params[key] ?? (telegram ? schema.default : undefined)}
                  secretPlaceholder={telegram && key === 'token' ? t('tg.inheritToken') : undefined}
                  optionLabel={telegram ? (value) => telegramOption(key, value) : undefined}
                  onChange={(v) => set(key, v)}
                />
              )}
              {hint && <span className="field__hint">{hint}</span>}
            </label>
            {telegram && key === 'token' && params.token === SECRET_MASK && (
              <button className="btn btn--ghost" type="button" onClick={() => set(key, undefined)}>
                {t('tg.useGlobalToken')}
              </button>
            )}
          </Fragment>
        )
      })}
    </div>
  )
}

function telegramHint(key: string) {
  if (key === 'chatId') return t('tg.nodeChatHint')
  if (key === 'onlyNew') return t('tg.onlyNewHint')
  if (key === 'threadId') return t('tg.threadHint')
}

function telegramOption(key: string, value: string | number) {
  if (key === 'language') return t('tg.language.' + value)
  if (key === 'minSeverity') return t('tg.severity.' + value)
  return String(value)
}

/** Источник «ZIP-архив»: загрузить архив и подставить его id. Распаковку и лимиты проверяет сервер. */
function ArchiveUpload({ value, onChange }: { value: unknown; onChange: (v: unknown) => void }) {
  const [state, setState] = useState<{ busy: boolean; error?: string; name?: string }>({ busy: false })
  async function upload(file: File) {
    setState({ busy: true, name: file.name })
    try {
      const { uploadId } = await api.upload(file)
      onChange(uploadId)
      setState({ busy: false, name: file.name })
    } catch (err) {
      setState({ busy: false, error: errorMessage(err) })
    }
  }
  return (
    <div className="stack" style={{ gap: 6 }}>
      <input
        className="input"
        type="file"
        accept=".zip,application/zip"
        disabled={state.busy}
        onChange={(e) => { const f = e.target.files?.[0]; if (f) void upload(f) }}
      />
      <span className="field__hint">
        {state.busy ? t('pf.uploading', { name: state.name ?? '' }) : value ? t('pf.uploaded', { name: state.name ?? String(value) }) : t('pf.zipLimit')}
      </span>
      {state.error && <span className="field__hint" style={{ color: 'var(--bad)' }}>{state.error}</span>}
    </div>
  )
}

function Field({ schema, secret, value, emptyLabel, optionLabel, secretPlaceholder, onChange }: {
  schema: ParamSchema
  secret: boolean
  value: unknown
  emptyLabel?: string
  optionLabel?: (value: string | number) => string
  secretPlaceholder?: string
  onChange: (v: unknown) => void
}) {
  if (secret || schema.format === 'password') {
    const isMask = value === SECRET_MASK
    return (
      <input
        className="input"
        type="password"
        autoComplete="new-password"
        placeholder={isMask ? t('pf.secretSet') : secretPlaceholder ?? t('pf.secretUnset')}
        value={isMask ? '' : String(value ?? '')}
        onChange={(e) => onChange(e.target.value === '' && isMask ? SECRET_MASK : e.target.value)}
      />
    )
  }
  if (schema.enum) {
    const options = schema.enum
    return (
      <select
        className="select"
        value={String(value ?? '')}
        onChange={(event) => onChange(options.find((option) => String(option) === event.target.value))}
      >
        <option value="" disabled={!emptyLabel}>{emptyLabel ?? t('pf.choose')}</option>
        {options.map((option) => (
          <option key={String(option)} value={String(option)}>{optionLabel?.(option) ?? String(option)}</option>
        ))}
      </select>
    )
  }
  if (schema.type === 'boolean') {
    return <input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />
  }
  if (schema.type === 'integer' || schema.type === 'number') {
    return (
      <input
        className="input"
        type="number"
        min={schema.minimum}
        max={schema.maximum}
        value={value === undefined || value === null ? '' : String(value)}
        onChange={(e) => onChange(e.target.value === '' ? undefined : Number(e.target.value))}
      />
    )
  }
  return <input className="input" value={String(value ?? '')} onChange={(e) => onChange(e.target.value)} />
}
