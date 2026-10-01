import { describe, expect, it } from 'vitest'
import { ApiError, errorMessage, API_BASE } from '@/lib/api'

describe('api client helpers', () => {
  it('uses the relative /api base so the browser never needs the backend host', () => {
    expect(API_BASE).toBe('/api')
  })

  it('unwraps structured backend errors', () => {
    const error = new ApiError('failed', 400, {
      message: 'The uploaded dataset contains no records.',
      hint: 'Upload a CSV with a header row and at least one data row.',
    })
    expect(errorMessage(error)).toBe('The uploaded dataset contains no records.')
  })

  it('falls back to the plain message for string details', () => {
    expect(errorMessage(new ApiError('failed', 404, 'Prediction not found.'))).toBe('Prediction not found.')
  })
})
