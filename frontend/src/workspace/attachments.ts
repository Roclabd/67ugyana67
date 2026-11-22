import { TELEGRAM_ATTACHMENTS, type TelegramAttachmentFormat } from '../api/types'

/** Новый выбор вложений после переключения одного формата; порядок всегда канонический. */
export function toggleAttachment(
  value: readonly TelegramAttachmentFormat[],
  format: TelegramAttachmentFormat,
  checked: boolean,
): TelegramAttachmentFormat[] {
  return TELEGRAM_ATTACHMENTS.filter((item) => (item === format ? checked : value.includes(item)))
}
