import { describe, expect, it } from 'vitest'
import { toggleAttachment } from './attachments'

describe('toggleAttachment', () => {
  it('adds in canonical order, removes, and allows an empty selection', () => {
    expect(toggleAttachment(['html'], 'pdf', true)).toEqual(['pdf', 'html'])
    expect(toggleAttachment(['pdf', 'md'], 'md', true)).toEqual(['pdf', 'md'])
    expect(toggleAttachment(['html'], 'html', false)).toEqual([])
  })
})
