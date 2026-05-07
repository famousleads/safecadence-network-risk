import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Match the existing vanilla UI palette so screenshots stay
        // consistent across views ported from the old to the new UI.
        bg: "#0b1220",
        panel: "#111827",
        border: "#1f2937",
        muted: "#9ca3af",
        accent: "#6366f1",
        good: "#10b981",
        bad: "#ef4444",
        warn: "#f59e0b",
      },
    },
  },
  plugins: [],
};
export default config;
