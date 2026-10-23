'use client'

import { useTheme } from '@payloadcms/ui'
import React from 'react'

/** Light/dark switch in the top-right of the admin panel. Remembered per browser. */
export const ThemeToggle = () => {
  const { theme, setTheme } = useTheme()
  const next = theme === 'dark' ? 'light' : 'dark'
  return (
    <button
      type="button"
      className="csme-theme-toggle"
      onClick={() => setTheme(next)}
      title={`Switch to ${next} mode`}
      aria-label={`Switch to ${next} mode`}
    >
      <span className="csme-theme-toggle__icon" aria-hidden>
        {theme === 'dark' ? '☀' : '☾'}
      </span>
      <span className="csme-theme-toggle__label">{theme === 'dark' ? 'Light' : 'Dark'}</span>
    </button>
  )
}

export default ThemeToggle
