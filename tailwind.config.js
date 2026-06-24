/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './interface/templates/**/*.html',
    './interface/static/**/*.js'
  ],
  theme: {
    extend: {
      colors: {
        'bg-primary': '#121b33',
        'surface': '#1e3359',
        'surface-muted': '#1e3359',
        'surface-contrast': '#284878',
        'text-main': '#ffffff',
        'text-secondary': '#94a3b8',
        'accent': '#3b82f6',
        'accent-2': '#10b981',
        'warn': '#ef4444',
        'border-subtle': 'rgba(148, 163, 184, 0.12)',
      },
      fontFamily: {
        'sans': ['Plus Jakarta Sans', 'Segoe UI', 'system-ui', '-apple-system', 'sans-serif'],
      },
      fontSize: {
        'fluid-xs': 'clamp(0.65rem, 0.6rem + 0.25vw, 0.75rem)',
        'fluid-sm': 'clamp(0.75rem, 0.7rem + 0.25vw, 0.875rem)',
        'fluid-base': 'clamp(0.875rem, 0.8rem + 0.375vw, 1rem)',
        'fluid-lg': 'clamp(1rem, 0.9rem + 0.5vw, 1.125rem)',
        'fluid-xl': 'clamp(1.125rem, 1rem + 0.625vw, 1.25rem)',
        'fluid-2xl': 'clamp(1.25rem, 1rem + 1.25vw, 1.5rem)',
        'fluid-3xl': 'clamp(1.5rem, 1rem + 2.5vw, 1.875rem)',
        'fluid-4xl': 'clamp(1.75rem, 1rem + 3.75vw, 2.25rem)',
      },
      spacing: {
        'fluid-xs': 'clamp(0.25rem, 0.2rem + 0.25vw, 0.5rem)',
        'fluid-sm': 'clamp(0.5rem, 0.4rem + 0.5vw, 0.75rem)',
        'fluid-md': 'clamp(0.75rem, 0.6rem + 0.75vw, 1rem)',
        'fluid-lg': 'clamp(1rem, 0.8rem + 1vw, 1.5rem)',
        'fluid-xl': 'clamp(1.5rem, 1rem + 2.5vw, 2.5rem)',
        'fluid-2xl': 'clamp(2rem, 1rem + 5vw, 3rem)',
      },
      borderRadius: {
        'sm': '0.5rem',
        'md': '0.75rem',
        'lg': '1rem',
        'xl': '1.5rem',
      },
      boxShadow: {
        'soft': '0 10px 30px rgba(0, 0, 0, 0.25)',
        'card': '0 4px 12px rgba(0, 0, 0, 0.3)',
      },
      screens: {
        'xs': '320px',
        'sm': '640px',
        'md': '768px',
        'lg': '1024px',
        'xl': '1280px',
        '2xl': '1536px',
        '3xl': '1920px',
      },
      animation: {
        'slide-up': 'slideInUp 0.5s ease-out',
        'fade-in': 'fadeIn 0.3s ease-out',
      },
      keyframes: {
        slideInUp: {
          from: {
            opacity: '0',
            transform: 'translateY(20px)',
          },
          to: {
            opacity: '1',
            transform: 'translateY(0)',
          },
        },
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
};
