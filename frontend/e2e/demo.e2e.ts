import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { expect, test, type Locator, type Page } from '@playwright/test'
import type { Run, RunStarted } from '../src/api/types'

const fixtureUrl = new URL('./fixtures/', import.meta.url)
const archivePath = fileURLToPath(new URL('secrets.zip', fixtureUrl))
const propertiesPath = new URL('secrets.properties', fixtureUrl)
const stages = [
  { title: 'Ручной запуск', type: 'trigger.manual' },
  { title: 'ZIP-архив', type: 'source.archive' },
  { title: 'Разбор проекта', type: 'analyzer.parse' },
  { title: 'Поиск секретов', type: 'analyzer.secret' },
  { title: 'Собрать отчёт', type: 'output.report' },
]
const links = [
  { output: 'trigger', input: 'trigger' },
  { output: 'workspace', input: 'workspace' },
  { output: 'model', input: 'model' },
  { output: 'findings', input: 'findings' },
]

function addStage(page: Page, title: string) {
  return page.locator('.editor__palette').getByRole('button', { name: title, exact: true }).click()
}

function graphNode(page: Page, type: string) {
  return page.locator('.react-flow__node').filter({
    has: page.getByText(type, { exact: true }),
  })
}

async function chooseSearchResult(page: Page, query: string, result: RegExp) {
  await page.getByRole('textbox', { name: 'Что найти' }).fill(query)
  await page.getByRole('option', { name: result }).click()
}

async function connect(source: Locator, output: string, target: Locator, input: string) {
  const from = source.locator(`.react-flow__handle.source[data-handleid="${output}"]`)
  const to = target.locator(`.react-flow__handle.target[data-handleid="${input}"]`)
  await expect(from).toBeInViewport()
  await expect(to).toBeInViewport()
  await from.dragTo(to)
}

async function expectMaskedPage(page: Page, values: string[]) {
  const visibleText = await page.locator('body').innerText()
  expect(values.filter((value) => visibleText.includes(value)).length, 'В отчёте видны исходные значения секретов').toBe(0)
}

test('Обзор → поиск → граф проверки ZIP → отчёт с пятью замаскированными секретами', async ({ page, request }) => {
  await page.setViewportSize({ width: 1920, height: 1080 })
  const fixture = await readFile(propertiesPath, 'utf8')
  const values = fixture.trim().split(/\r?\n/).map((line) => line.split('=')[1])
  expect(values).toHaveLength(5)
  const workflowName = `E2E ZIP ${randomUUID()}`

  await test.step('Открыть редактор из обзора и собрать граф вручную', async () => {
    await page.goto('/')
    await expect(page.getByRole('link', { name: 'Обзор', exact: true })).toHaveAttribute('aria-current', 'page')
    await expect(page.getByText('Серверный режим', { exact: true })).toBeVisible()
    await page.keyboard.press('Control+k')
    await chooseSearchResult(page, 'редактирование графов', /^Конструктор сценариев/)
    await expect(page).toHaveURL(/\/workflows\/[^/]+$/)
    await expect(page.getByRole('button', { name: 'Проверить схему' })).toBeVisible()
    await page.keyboard.press('Control+k')
    await chooseSearchResult(page, 'Новый сценарий', /^Новый сценарий/)
    await expect(page).toHaveURL(/\/workflows\/new$/)

    await page.locator('.editor__name').fill(workflowName)
    for (const stage of stages) await addStage(page, stage.title)
    const nodes = page.locator('.react-flow__node')
    const edges = page.locator('.react-flow__edge')
    await expect(nodes).toHaveCount(stages.length)
    await page.locator('.react-flow__controls-fitview').click()
    for (const [index, { output, input }] of links.entries()) {
      await connect(graphNode(page, stages[index].type), output, graphNode(page, stages[index + 1].type), input)
      await expect(edges).toHaveCount(index + 1)
    }
    await page.getByRole('button', { name: 'Проверить схему' }).click()
    await expect(page.getByText('Граф корректен', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Сохранить', exact: true }).click()
    await expect(page).toHaveURL(/\/workflows\/[a-f\d-]{36}$/)
    await page.reload()
    await expect(page.locator('.editor__name')).toHaveValue(workflowName)
    await expect(nodes).toHaveCount(stages.length)
    await expect(edges).toHaveCount(links.length)
  })

  const runId = await test.step('Загрузить ZIP и дождаться SUCCESS на сервере', async () => {
    await graphNode(page, 'source.archive').click()
    await page.locator('input[type="file"]').setInputFiles(archivePath)
    await expect(page.getByText('Архив загружен: secrets.zip', { exact: true })).toBeVisible()
    const runResponse = page.waitForResponse((response) =>
      response.request().method() === 'POST' && /\/api\/workflows\/[^/]+\/run$/.test(response.url()),
    )
    await page.getByRole('button', { name: /Запустить$/ }).click()
    const response = await runResponse
    expect(response.ok()).toBe(true)
    const { runId } = await response.json() as RunStarted
    const runUrl = `/api/runs/${runId}`
    await expect.poll(async () => {
      const run = await request.get(runUrl)
      expect(run.ok()).toBe(true)
      return ((await run.json()) as Run).status
    }, { timeout: 60_000, message: `Статус запуска ${runId}` }).toBe('SUCCESS')
    const run = await request.get(runUrl)
    const { report } = await run.json() as Run
    expect(report?.findings.map(({ category, path, line, secretMasked }) => ({
      category, path, line, secretMasked,
    })).sort((a, b) => (a.line ?? 0) - (b.line ?? 0))).toEqual(values.map((_, index) => ({
      category: 'SECRET',
      path: 'secrets.properties',
      line: index + 1,
      secretMasked: '****',
    })))
    return runId
  })

  await test.step('Проверить отчёт и его прямую ссылку после перезагрузки', async () => {
    await page.getByTitle(`Запуск ${runId} — открыть подробности`).click()
    await page.getByRole('button', { name: 'Отчёт', exact: true }).click()
    await expect(page).toHaveURL(new RegExp(`/runs/${runId}/report$`))
    const heading = page.getByRole('heading', { name: 'Отчёт проверки', exact: true })
    await expect(heading).toBeVisible()
    await expect(page.getByText(/\b5 находок/)).toBeVisible()
    await expectMaskedPage(page, values)
    await page.reload()
    await expect(heading).toBeVisible()
    await expect(page.getByText(/\b5 находок/)).toBeVisible()
    await expectMaskedPage(page, values)

    await page.getByRole('link', { name: 'Полный технический отчёт' }).click()
    await expect(page.getByRole('heading', { name: 'Находки', exact: true })).toBeVisible()
    const rows = page.getByRole('table').locator('tbody').getByRole('row')
    await expect(rows).toHaveCount(values.length)
    for (const row of await rows.all()) {
      await expect(row.getByRole('cell', { name: '****', exact: true })).toBeVisible()
    }
    await expectMaskedPage(page, values)
  })
})

test.describe('Мобильный экран 390 px', () => {
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })

  test('меню ведёт в конструктор, параметры ZIP-этапа доступны', async ({ page }) => {
    await page.goto('/')
    const menu = page.getByRole('button', { name: 'Меню навигации' })
    const constructor = page.getByRole('navigation', { name: 'Проверки' })
      .getByRole('link', { name: 'Конструктор', exact: true })
    await expect(menu).toHaveAttribute('aria-expanded', 'false')
    await menu.tap()
    await expect(menu).toHaveAttribute('aria-expanded', 'true')
    await constructor.tap()
    await expect(menu).toHaveAttribute('aria-expanded', 'false')
    await expect(page).toHaveURL(/\/workflows\/[^/]+$/)

    await page.getByRole('button', { name: 'Поиск по рабочему пространству' }).tap()
    await chooseSearchResult(page, 'Новый сценарий', /^Новый сценарий/)
    await expect(page).toHaveURL(/\/workflows\/new$/)
    await page.locator('.editor__palette').getByRole('button', { name: 'ZIP-архив', exact: true }).tap()
    const subdir = page.getByRole('textbox', { name: 'Папка проекта в архиве' })
    await expect(subdir).toBeVisible()
    await subdir.fill('module')
    await expect(subdir).toHaveValue('module')
  })
})
