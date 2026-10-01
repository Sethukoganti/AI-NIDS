import { describe, expect, it } from 'vitest'
import { attackColor, formatBytes, formatCompact, formatNumber, formatPercent, riskLabel, RISK_COLORS } from '@/lib/format'

describe('format helpers', () => {
  it('formats percentages with two decimals by default', () => {
    expect(formatPercent(0.9959430496019596)).toBe('99.59%')
    expect(formatPercent(0.5, 0)).toBe('50%')
  })

  it('never prints NaN for missing values', () => {
    expect(formatNumber(null)).toBe('—')
    expect(formatNumber(undefined)).toBe('—')
    expect(formatPercent(undefined)).toBe('—')
    expect(formatBytes(0)).toBe('—')
  })

  it('compacts large numbers', () => {
    expect(formatCompact(2_830_743)).toBe('2.83M')
  })

  it('scales byte sizes', () => {
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(1536)).toBe('1.5 KB')
  })

  it('maps attack families to stable colours with a fallback', () => {
    expect(attackColor('DDoS')).toBe('#ef4444')
    expect(attackColor('Port Scanning')).toBe('#eab308')
    expect(attackColor('Something New')).toBe('#64748b')
  })

  it('keeps the risk palette aligned with the documented rules', () => {
    expect(RISK_COLORS.critical).toBe('#ef4444')
    expect(riskLabel('medium')).toBe('Medium')
  })
})
