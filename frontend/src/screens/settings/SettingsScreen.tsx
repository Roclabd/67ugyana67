import { useState } from 'react'
import { api } from '../../api/client'
import { useAction, useApi } from '../../api/useApi'
import type { LlmProvider, LlmSettings, LlmSettingsUpdate } from '../../api/types'
import { AsyncView, Card, ErrorBox, Page } from '../../ui'
import { t } from '../../i18n'
import { useDemo } from '../../api/demo'

export type SettingsScreenProps = Record<string, never>

const PROVIDER_URLS: Record<LlmProvider, string> = {
  'openai-compatible': '',
  groq: 'https://api.groq.com/openai/v1',
  openrouter: 'https://openrouter.ai/api/v1',
  ollama: 'http://localhost:11434/v1',
  vllm: 'http://localhost:8000/v1',
}

const PROVIDERS: Array<{ value: LlmProvider; label: string }> = [
  { value: 'openai-compatible', get label() { return t('set.openai') } },
  { value: 'groq', label: 'Groq' },
  { value: 'openrouter', label: 'OpenRouter' },
  { value: 'ollama', label: 'Ollama' },
  { value: 'vllm', label: 'vLLM' },
]

type SettingsForm = LlmSettings & { apiKey: string }

function formFromSettings(settings: LlmSettings): SettingsForm {
  return { ...settings, apiKey: '' }
}

export function SettingsScreen(_props: SettingsScreenProps) {
  const demo = useDemo()
  const settings = useApi(() => api.getLlmSettings(), [])
  const save = useAction((payload: LlmSettingsUpdate) => api.updateLlmSettings(payload))
  const [form, setForm] = useState<SettingsForm | null>(null)
  const [saved, setSaved] = useState(false)

  return (
    <Page
      title={t('set.title')}
      subtitle={t('set.sub')}
    >
      {save.error && <ErrorBox error={save.error} />}
      <AsyncView state={settings.state} onRetry={settings.reload}>
        {(loadedSettings) => {
          const values = form ?? formFromSettings(loadedSettings)

          function changeProvider(provider: LlmProvider) {
            const currentExample = PROVIDER_URLS[values.provider]
            const baseUrl = !values.baseUrl || values.baseUrl === currentExample
              ? PROVIDER_URLS[provider]
              : values.baseUrl
            setForm({ ...values, provider, baseUrl })
            setSaved(false)
          }

          function changeField(patch: Partial<SettingsForm>) {
            setForm({ ...values, ...patch })
            setSaved(false)
          }

          async function handleSave() {
            const payload: LlmSettingsUpdate = {
              provider: values.provider,
              baseUrl: values.baseUrl,
              model: values.model,
              ...(values.apiKey.length > 0 ? { apiKey: values.apiKey } : {}),
            }
            const updated = await save.run(payload)
            if (updated) {
              setForm(formFromSettings(updated))
              setSaved(true)
            }
          }

          return (
            <Card title={t('set.params')}>
              <div className="stack">
                <label className="field">
                  <span className="field__label">{t('set.provider')}</span>
                  <select
                    className="select"
                    value={values.provider}
                    onChange={(event) => changeProvider(event.target.value as LlmProvider)}
                  >
                    {PROVIDERS.map((provider) => (
                      <option key={provider.value} value={provider.value}>{provider.label}</option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span className="field__label">Base URL</span>
                  <input
                    className="input"
                    type="url"
                    value={values.baseUrl}
                    onChange={(event) => changeField({ baseUrl: event.target.value })}
                    placeholder="https://api.example.com/v1"
                  />
                </label>
                <label className="field">
                  <span className="field__label">{t('set.model')}</span>
                  <input
                    className="input"
                    value={values.model}
                    onChange={(event) => changeField({ model: event.target.value })}
                    placeholder={t('set.modelPh')}
                  />
                </label>
                <label className="field">
                  <span className="field__label">{t('set.key')}</span>
                  <input
                    className="input"
                    type="password"
                    autoComplete="new-password"
                    value={values.apiKey}
                    onChange={(event) => changeField({ apiKey: event.target.value })}
                    placeholder={t('set.keyPh')}
                  />
                  <span className="field__hint">{values.apiKeySet ? t('set.keySet') : t('set.keyUnset')}. {t('set.keyNote')}</span>
                </label>
                <div className="row">
                  <button
                    className="btn btn--primary"
                    type="button"
                    disabled={save.pending || demo}
                    title={demo ? t('demo.readonly') : undefined}
                    onClick={() => void handleSave()}
                  >
                    {save.pending ? t('set.saving') : t('ed.save')}
                  </button>
                  {saved && <span className="alert alert--info">{t('set.saved')}</span>}
                </div>
              </div>
            </Card>
          )
        }}
      </AsyncView>
    </Page>
  )
}
