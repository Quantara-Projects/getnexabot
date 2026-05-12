import type { Config } from "tailwindcss";
import defaultTheme from "tailwindcss/defaultTheme";

const config: Config = {
    darkMode: ["class"],
    content: [
        "./pages/**/*.{ts,tsx}",
        "./components/**/*.{ts,tsx}",
        "./app/**/*.{ts,tsx}",
        "./src/**/*.{ts,tsx}",
        "./index.html",
    ],
    prefix: "",
    theme: {
        container: {
            center: true,
            padding: {
                DEFAULT: "1.5rem",
                sm: "2rem",
                lg: "2.5rem",
            },
            screens: {
                "2xl": "1280px",
            },
        },
        extend: {
            colors: {
                border: "hsl(var(--border) / <alpha-value>)",
                input: "hsl(var(--input) / <alpha-value>)",
                ring: "hsl(var(--ring) / <alpha-value>)",
                background: "hsl(var(--background) / <alpha-value>)",
                foreground: "hsl(var(--foreground) / <alpha-value>)",
                primary: {
                    50: "hsl(175 80% 95%)",
                    100: "hsl(175 75% 88%)",
                    200: "hsl(175 70% 75%)",
                    300: "hsl(175 65% 60%)",
                    400: "hsl(175 72% 50%)",
                    500: "hsl(175 80% 42%)",
                    600: "hsl(175 85% 35%)",
                    700: "hsl(175 90% 25%)",
                    800: "hsl(175 92% 18%)",
                    900: "hsl(175 95% 12%)",
                    DEFAULT: "hsl(175 72% 50%)",
                    foreground: "hsl(0 0% 100%)",
                },
                success: {
                    50: "hsl(167 71% 93%)",
                    500: "hsl(167 71% 45%)",
                    700: "hsl(167 71% 25%)",
                },
                alert: {
                    50: "hsl(39 100% 93%)",
                    500: "hsl(39 100% 55%)",
                    700: "hsl(39 100% 35%)",
                },
                error: {
                    50: "hsl(0 100% 93%)",
                    500: "hsl(0 100% 53%)",
                    700: "hsl(0 100% 33%)",
                },
                neutral: {
                    50: "hsl(210 20% 98%)",
                    100: "hsl(210 20% 94%)",
                    200: "hsl(210 20% 86%)",
                    300: "hsl(210 20% 72%)",
                    400: "hsl(210 20% 58%)",
                    500: "hsl(210 20% 44%)",
                    600: "hsl(210 20% 34%)",
                    700: "hsl(210 20% 24%)",
                    800: "hsl(210 20% 16%)",
                    900: "hsl(210 20% 8%)",
                    DEFAULT: "hsl(210 20% 58%)",
                },
            },
            spacing: {
                xs: "0.5rem",
                sm: "1rem",
                md: "1.5rem",
                lg: "2rem",
                xl: "3rem",
                "2xl": "4rem",
                "3xl": "6rem",
            },
            fontSize: {
                "display-1": ["48px", { lineHeight: "52px", fontWeight: "700", letterSpacing: "-0.5px" }],
                "display-2": ["36px", { lineHeight: "40px", fontWeight: "600", letterSpacing: "-0.3px" }],
                h1: ["28px", { lineHeight: "34px", fontWeight: "600" }],
                h2: ["20px", { lineHeight: "28px", fontWeight: "600" }],
                h3: ["16px", { lineHeight: "24px", fontWeight: "600" }],
                lg: ["16px", { lineHeight: "24px", fontWeight: "400" }],
                base: ["14px", { lineHeight: "22px", fontWeight: "400" }],
                sm: ["12px", { lineHeight: "18px", fontWeight: "400" }],
                "mono-lg": ["14px", { lineHeight: "20px", fontWeight: "500" }],
                mono: ["12px", { lineHeight: "18px", fontWeight: "400" }],
            },
            fontFamily: {
                sans: ["Inter", ...defaultTheme.fontFamily.sans],
                mono: ["Fira Code", "JetBrains Mono", ...defaultTheme.fontFamily.mono],
            },
            borderRadius: {
                none: "0",
                sm: "6px",
                base: "8px",
                lg: "12px",
                xl: "16px",
                "2xl": "20px",
                "3xl": "24px",
                full: "9999px",
            },
            boxShadow: {
                none: "none",
                sm: "0 1px 2px 0 rgba(0, 0, 0, 0.04)",
                base: "0 1px 3px 0 rgba(0, 0, 0, 0.06)",
                md: "0 4px 8px -2px rgba(0, 0, 0, 0.08)",
                lg: "0 8px 20px -4px rgba(0, 0, 0, 0.08)",
                xl: "0 12px 32px -8px rgba(0, 0, 0, 0.10)",
                "2xl": "0 20px 48px -12px rgba(0, 0, 0, 0.12)",
                "soft": "0 2px 16px rgba(0, 0, 0, 0.04)",
                "inner-sm": "inset 0 1px 2px rgba(0, 0, 0, 0.04)",
            },
            keyframes: {
                fadeIn: {
                    "0%": { opacity: "0" },
                    "100%": { opacity: "1" },
                },
                fadeUp: {
                    "0%": { opacity: "0", transform: "translateY(12px)" },
                    "100%": { opacity: "1", transform: "translateY(0)" },
                },
                scaleIn: {
                    "0%": { opacity: "0", transform: "scale(0.96)" },
                    "100%": { opacity: "1", transform: "scale(1)" },
                },
                slideIn: {
                    "0%": { transform: "translateX(-100%)" },
                    "100%": { transform: "translateX(0)" },
                },
                slideInRight: {
                    "0%": { transform: "translateX(100%)" },
                    "100%": { transform: "translateX(0)" },
                },
                pulse: {
                    "0%, 100%": { opacity: "1" },
                    "50%": { opacity: "0.7" },
                },
                float: {
                    "0%, 100%": { transform: "translateY(0)" },
                    "50%": { transform: "translateY(-8px)" },
                },
                shimmer: {
                    "0%": { backgroundPosition: "-200% 0" },
                    "100%": { backgroundPosition: "200% 0" },
                },
                wave: {
                    "0%": { transform: "rotate(0deg)" },
                    "25%": { transform: "rotate(3deg)" },
                    "50%": { transform: "rotate(0deg)" },
                    "75%": { transform: "rotate(-3deg)" },
                    "100%": { transform: "rotate(0deg)" },
                },
                typewriter: {
                    "0%": { width: "0" },
                    "100%": { width: "100%" },
                },
                blink: {
                    "0%, 100%": { opacity: "1" },
                    "50%": { opacity: "0" },
                },
            },
            animation: {
                "fade-in": "fadeIn 0.4s ease-out",
                "fade-up": "fadeUp 0.5s ease-out",
                "scale-in": "scaleIn 0.4s ease-out",
                "slide-in": "slideIn 0.25s ease-out",
                "slide-in-right": "slideInRight 0.25s ease-out",
                "pulse": "pulse 2s ease-in-out infinite",
                "float": "float 3s ease-in-out infinite",
                "shimmer": "shimmer 2s linear infinite",
                "wave": "wave 2s ease-in-out infinite",
                "typewriter": "typewriter 2s steps(40) forwards",
                "blink": "blink 1s step-end infinite",
            },
            backgroundImage: {
                "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
                "gradient-conic": "conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))",
            },
        },
    },
    plugins: [require("tailwindcss-animate")],
};

export default config;