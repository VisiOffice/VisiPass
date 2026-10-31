/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,ts}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      colors: {
        ink: {
          50: '#f8fafc', 100: '#f1f5f9', 200: '#e2e8f0', 300: '#cbd5e1', 400: '#94a3b8',
          500: '#64748b', 600: '#475569', 700: '#334155', 800: '#1e293b', 900: '#0f172a', 950: '#08090d',
        },
        // The approval window and extension's default palette (Tokyo Night), so
        // the demos look like the product does out of the box.
        tn: {
          bg: '#1a1b26', well: '#16161e', fg: '#c0caf5', muted: '#9aa5ce',
          accent: '#7aa2f7', danger: '#f7768e', green: '#9ece6a', yellow: '#e0af68', purple: '#bb9af7',
        },
      },
    },
  },
};
