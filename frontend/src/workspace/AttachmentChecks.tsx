import { TELEGRAM_ATTACHMENTS, type TelegramAttachmentFormat } from '../api/types'
import { t } from '../i18n'
import { toggleAttachment } from './attachments'

/** Группа чекбоксов «Вложения»: можно выбрать несколько форматов или не выбрать ни одного. */
export function AttachmentChecks({ value, onChange, disabled }: {
  value: readonly TelegramAttachmentFormat[]
  onChange: (next: TelegramAttachmentFormat[]) => void
  disabled?: boolean
}) {
  return (
    <div className="row" role="group" aria-label={t('tg.attachments')}>
      {TELEGRAM_ATTACHMENTS.map((format) => (
        <label key={format} className="row" style={{ gap: 4 }}>
          <input
            type="checkbox"
            disabled={disabled}
            checked={value.includes(format)}
            onChange={(event) => onChange(toggleAttachment(value, format, event.target.checked))}
          />
          <span>{t('tg.format.' + format)}</span>
        </label>
      ))}
    </div>
  )
}
