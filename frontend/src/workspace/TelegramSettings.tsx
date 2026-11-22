import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { ApiError, api, USE_MOCKS } from '../api/client'
import { TELEGRAM_CHAT_LIST_MAX_LENGTH, type TelegramAttachmentFormat, type TelegramSettingsUpdate } from '../api/types'
import { useAction, useApi } from '../api/useApi'
import { getLang, t, tOr } from '../i18n'
import { AsyncView, Card, ErrorBox } from '../ui'
import { AttachmentChecks } from './AttachmentChecks'
import { useDemo } from '../api/demo'

type Draft = { token?: string; chatId: string; attachments: TelegramAttachmentFormat[] }

async function telegramAction<T>(request: Promise<T>): Promise<T> {
  try {
    return await request
  } catch (error) {
    if (error instanceof ApiError) throw new Error(tOr('tg.error.' + error.code, error.message))
    throw error
  }
}

export function TelegramSettings() {
  const demo = useDemo()
  const { hash } = useLocation()
  const settings = useApi(api.getTelegramSettings, [])
  const save = useAction((payload: TelegramSettingsUpdate) => telegramAction(api.updateTelegramSettings(payload)))
  const test = useAction((payload: { token?: string; chatId: string }) => telegramAction(
    api.testTelegram({ ...payload, language: getLang() }),
  ))
  const [draft, setDraft] = useState<Draft>()
  const [feedback, setFeedback] = useState<'saved' | 'sent'>()
  const [action, setAction] = useState<'save' | 'test'>()

  useEffect(() => {
    if (hash === '#telegram') document.getElementById('telegram')?.scrollIntoView({ block: 'start' })
  }, [hash])

  return (
    <section id="telegram" aria-label={t('tg.settings')}>
      <Card title={t('tg.settings')}>
        <AsyncView state={settings.state} onRetry={settings.reload}>
          {(loaded) => {
            const legacy = (loaded as { format?: string }).format
            const values = draft ?? {
              chatId: loaded.chatId ?? '',
              // старый сервер отдаёт один format вместо списка attachments
              attachments: loaded.attachments
                ?? (legacy && legacy !== 'none' ? [legacy as TelegramAttachmentFormat] : []),
            }
            const busy = save.pending || test.pending
            const error = action === 'save' ? save.error : action === 'test' ? test.error : null
            const update = (patch: Partial<Draft>) => {
              setDraft({ ...values, ...patch })
              setFeedback(undefined)
              setAction(undefined)
            }

            async function saveSettings() {
              setAction('save')
              setFeedback(undefined)
              const updated = await save.run(values)
              if (updated) {
                setDraft(undefined)
                setFeedback('saved')
                settings.reload()
              }
            }

            async function testConnection() {
              setAction('test')
              setFeedback(undefined)
              if (await test.run({ token: values.token, chatId: values.chatId })) setFeedback('sent')
            }

            return (
              <form className="stack" onSubmit={(event) => { event.preventDefault(); void saveSettings() }}>
                <p className="muted">{t('tg.defaultsHint')}</p>
                <p className="field__hint" data-testid="tg-bot-commands-hint">{t('tg.botCommandsHint')}</p>
                <label className="field">
                  <span className="field__label">{t('tg.token')}</span>
                  <input
                    className="input"
                    type="password"
                    autoComplete="new-password"
                    maxLength={150}
                    disabled={busy}
                    value={values.token ?? ''}
                    placeholder={values.token === '' ? t('tg.tokenPlaceholder') : loaded.token || t('tg.tokenPlaceholder')}
                    onChange={(event) => update({ token: event.target.value || undefined })}
                  />
                </label>
                {loaded.tokenSaved && (
                  <div className="row">
                    <button
                      className="btn btn--ghost"
                      type="button"
                      disabled={busy}
                      onClick={() => update({ token: values.token === '' ? undefined : '' })}
                    >
                      {t(values.token === '' ? 'tg.keepToken' : 'tg.useEnvToken')}
                    </button>
                  </div>
                )}
                <label className="field">
                  <span className="field__label">{t('tg.chatId')}</span>
                  <textarea
                    className="input"
                    rows={3}
                    autoComplete="off"
                    maxLength={TELEGRAM_CHAT_LIST_MAX_LENGTH}
                    disabled={busy}
                    value={values.chatId}
                    onChange={(event) => update({ chatId: event.target.value })}
                  />
                  <span className="field__hint">{t('tg.chatHint')}</span>
                </label>
                <div className="field">
                  <span className="field__label">{t('tg.attachments')}</span>
                  <AttachmentChecks
                    value={values.attachments}
                    disabled={busy}
                    onChange={(attachments) => update({ attachments })}
                  />
                  <span className="field__hint">{t('tg.attachmentsHint')}</span>
                </div>
                <div className="row">
                  <button className="btn btn--primary" type="submit" disabled={busy || demo} title={demo ? t('demo.readonly') : undefined}>
                    {t(save.pending ? 'set.saving' : 'ed.save')}
                  </button>
                  <button
                    className="btn"
                    type="button"
                    disabled={busy || USE_MOCKS || demo}
                    aria-describedby="telegram-test-hint"
                    onClick={() => void testConnection()}
                  >
                    {t(test.pending ? 'tg.testing' : 'tg.test')}
                  </button>
                </div>
                <span id="telegram-test-hint" className="field__hint">
                  {t(USE_MOCKS ? 'tg.demoHint' : 'tg.testHint')}
                </span>
                {error && <ErrorBox error={error} />}
                {feedback && <p role="status" className="alert alert--info">{t('tg.' + feedback)}</p>}
              </form>
            )
          }}
        </AsyncView>
      </Card>
    </section>
  )
}
