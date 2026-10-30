/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        signal: '#FF2E2E',
        'deep-red': '#8B1111',
        'jet-black': '#090909',
        'clean-white': '#FFFFFF',
        'warm-gray': '#B8B1AA',
        clay: {
          bg: '#090909',
          surface: '#141111',
          'surface-hover': '#1a1414',
          subtle: '#100d0d',
          inset: '#0d0a0a',
          border: 'rgba(139, 17, 17, 0.35)',
          'border-active': 'rgba(255, 46, 46, 0.55)',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      }
    },
  },
  plugins: [],
}
