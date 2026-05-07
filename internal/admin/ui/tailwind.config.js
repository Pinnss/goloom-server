/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./internal/admin/ui/**/*.templ",
    "./internal/admin/ui/**/*_templ.go",
  ],
  theme: {
    extend: {
      colors: {
        // Mirror Android client's design/Tokens.kt — neutral dark palette
        // with a single bright "active" green.
        bg: "#0e1014",
        panel: "#161a22",
        panel2: "#1d2230",
        line: "#232938",
        muted: "#888",
        accent: "#4CD964",   // android client status-on green
        warn: "#a80",
        danger: "#e55",
      },
      fontFamily: {
        sans: ["system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["ui-monospace", "Menlo", "Consolas", "monospace"],
      },
      keyframes: {
        blink: {
          "0%, 92%, 100%": { transform: "scaleY(1)" },
          "95%, 97%": { transform: "scaleY(0.05)" },
        },
        pulse2: {
          "0%, 100%": { opacity: "0.4" },
          "50%": { opacity: "1" },
        },
      },
      animation: {
        blink: "blink 4s ease-in-out infinite",
        pulse2: "pulse2 1.4s ease-in-out infinite",
      },
    },
  },
  plugins: [],
  safelist: [
    // Phase color classes referenced dynamically from Go code so Tailwind's
    // template scanner can see them.
    "text-accent", "bg-accent", "border-accent",
    "text-warn", "bg-warn", "border-warn",
    "text-danger", "bg-danger", "border-danger",
    "text-muted",
  ],
};
