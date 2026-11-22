import { describe, expect, it } from 'vitest'
import type { NodeDefinition } from '../api/types'
import { featureItems, nodeItems, search } from './searchIndex'

const items = [
  ...featureItems({ latestRunId: 'r1', firstWorkflowId: 'w1' }),
  ...nodeItems([
    { type: 'notify.telegram', title: 'Отправить в Telegram', category: 'OUTPUT', description: 'Сообщение в чат', inputs: [], outputs: [], paramsSchema: {}, secretParams: [] },
    { type: 'analyzer.secret', title: 'Поиск секретов', category: 'ANALYZER', inputs: [], outputs: [], paramsSchema: {}, secretParams: [] },
  ] as unknown as NodeDefinition[], '/workflows/w1'),
]

describe('поиск по функциям программы', () => {
  it('«редактирование графов» ведёт в конструктор', () => {
    expect(search(items, 'редактирование графов')[0]).toMatchObject({ name: 'Конструктор сценариев', path: '/workflows/w1' })
  })

  it('находит по синонимам и без учёта регистра и ё', () => {
    expect(search(items, 'нейросеть ключ')[0].path).toBe('/settings')
    expect(search(items, 'SARIF')[0]).toMatchObject({ name: 'Скачать отчёт', path: '/runs/r1/report' })
    expect(search(items, 'отчет на почту')[0].name).toBe('Отчёт на почту')
    expect(search(items, 'сгенерировать сценарий')[0].path).toBe('/workflows/new?generate=1')
  })

  it('ноды каталога ищутся по названию и по типу', () => {
    expect(search(items, 'секрет').map((i) => i.name)).toContain('Поиск секретов')
    expect(search(items, 'notify telegram')[0].name).toBe('Отправить в Telegram')
  })

  it('английские ключевые слова работают и при русском интерфейсе', () => {
    expect(search(items, 'edit graph')[0].path).toBe('/workflows/w1')
    expect(search(items, 'download report')[0]).toMatchObject({ id: 'download', path: '/runs/r1/report' })
    expect(search(items, 'llm model key')[0].path).toBe('/settings')
  })

  it('все слова запроса обязательны; пустой запрос — пусто', () => {
    expect(search(items, 'граф абракадабра')).toEqual([])
    expect(search(items, '   ')).toEqual([])
  })
})
