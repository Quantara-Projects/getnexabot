# NexaBot Tailwind Configuration & Token Implementation

This is the practical Tailwind setup to implement the design system.

## Complete tailwind.config.ts

Replace your existing `tailwind.config.ts` with this configuration:

```typescript
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
        DEFAULT: "1rem",
        sm: "2rem",
        lg: "2rem",
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
          50: "hsl(224 71% 96%)",
          100: "hsl(224 71% 90%)",
          200: "hsl(224 71% 80%)",
          300: "hsl(224 71% 70%)",
          400: "hsl(224 71% 55%)",
          500: "hsl(224 100% 50%)", // #0F6FFF - Core brand blue
          600: "hsl(224 100% 45%)",
          700: "hsl(224 100% 35%)",
          800: "hsl(224 100% 25%)",
          900: "hsl(224 100% 15%)",
          DEFAULT: "hsl(224 100% 50%)",
          foreground: "hsl(0 0% 100%)",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary) / <alpha-value>)",
          foreground: "hsl(var(--secondary-foreground) / <alpha-value>)",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive) / <alpha-value>)",
          foreground: "hsl(var(--destructive-foreground) / <alpha-value>)",
        },
        muted: {
          DEFAULT: "hsl(var(--muted) / <alpha-value>)",
          foreground: "hsl(var(--muted-foreground) / <alpha-value>)",
        },
        accent: {
          DEFAULT: "hsl(var(--accent) / <alpha-value>)",
          foreground: "hsl(var(--accent-foreground) / <alpha-value>)",
        },
        popover: {
          DEFAULT: "hsl(var(--popover) / <alpha-value>)",
          foreground: "hsl(var(--popover-foreground) / <alpha-value>)",
        },
        card: {
          DEFAULT: "hsl(var(--card) / <alpha-value>)",
          foreground: "hsl(var(--card-foreground) / <alpha-value>)",
        },
        // Success colors
        success: {
          50: "hsl(167 71% 93%)",
          100: "hsl(167 71% 88%)",
          200: "hsl(167 71% 78%)",
          300: "hsl(167 71% 65%)",
          400: "hsl(167 71% 55%)",
          500: "hsl(167 71% 45%)", // #10B981 - Teal success
          600: "hsl(167 71% 35%)",
          700: "hsl(167 71% 25%)",
          800: "hsl(167 71% 15%)",
          DEFAULT: "hsl(167 71% 45%)",
        },
        // Alert/Warning colors
        alert: {
          50: "hsl(39 100% 93%)",
          100: "hsl(39 100% 88%)",
          200: "hsl(39 100% 78%)",
          300: "hsl(39 100% 68%)",
          400: "hsl(39 100% 60%)",
          500: "hsl(39 100% 55%)", // #F59E0B - Amber alert
          600: "hsl(39 100% 45%)",
          700: "hsl(39 100% 35%)",
          800: "hsl(39 100% 25%)",
          DEFAULT: "hsl(39 100% 55%)",
        },
        // Error colors (replaces destructive in some contexts)
        error: {
          50: "hsl(0 100% 93%)",
          100: "hsl(0 100% 88%)",
          200: "hsl(0 100% 78%)",
          300: "hsl(0 100% 68%)",
          400: "hsl(0 100% 60%)",
          500: "hsl(0 100% 53%)", // #EF4444 - Clean red
          600: "hsl(0 100% 45%)",
          700: "hsl(0 100% 33%)",
          800: "hsl(0 100% 20%)",
          DEFAULT: "hsl(0 100% 53%)",
        },
        // Neutral grays
        gray: {
          50: "hsl(210 40% 96%)", // Almost white
          100: "hsl(210 40% 92%)",
          200: "hsl(210 40% 86%)",
          300: "hsl(210 40% 74%)", // Light gray
          400: "hsl(210 40% 63%)",
          500: "hsl(210 40% 51%)", // #6B7280 - Mid gray
          600: "hsl(210 40% 42%)",
          700: "hsl(210 40% 33%)", // #1E293B - Dark gray
          800: "hsl(210 40% 20%)", // #111832 - Very dark
          900: "hsl(210 40% 6%)", // #0A0E27 - Almost black (brand dark)
          DEFAULT: "hsl(210 40% 51%)",
        },
        // Crypto/Web3 accent (use sparingly)
        crypto: {
          50: "hsl(258 71% 93%)",
          100: "hsl(258 71% 88%)",
          200: "hsl(258 71% 78%)",
          300: "hsl(258 71% 65%)",
          400: "hsl(258 71% 55%)",
          500: "hsl(258 71% 50%)", // #8B5CF6 - Purple
          600: "hsl(258 71% 42%)",
          700: "hsl(258 71% 35%)",
          800: "hsl(258 71% 25%)",
          DEFAULT: "hsl(258 71% 50%)",
        },
      },
      spacing: {
        xs: "0.5rem", // 8px
        sm: "1rem", // 16px
        md: "1.5rem", // 24px
        lg: "2rem", // 32px
        xl: "3rem", // 48px
        "2xl": "4rem", // 64px
        "3xl": "6rem", // 96px
      },
      fontSize: {
        // Display sizes (hero/marketing)
        "display-1": [
          "48px",
          {
            lineHeight: "56px",
            fontWeight: "700",
            letterSpacing: "-0.5px",
          },
        ],
        "display-2": [
          "36px",
          {
            lineHeight: "44px",
            fontWeight: "600",
            letterSpacing: "-0.3px",
          },
        ],
        // Heading sizes
        h1: ["28px", { lineHeight: "36px", fontWeight: "600" }],
        h2: ["20px", { lineHeight: "28px", fontWeight: "600" }],
        h3: ["16px", { lineHeight: "24px", fontWeight: "600" }],
        // Body sizes
        lg: ["16px", { lineHeight: "24px", fontWeight: "400" }], // Primary body text
        base: ["14px", { lineHeight: "22px", fontWeight: "400" }], // Default UI text
        sm: ["12px", { lineHeight: "18px", fontWeight: "400" }], // Small/secondary text
        // Mono sizes (code/technical)
        "mono-lg": ["14px", { lineHeight: "20px", fontWeight: "500" }],
        mono: ["12px", { lineHeight: "18px", fontWeight: "400" }],
      },
      fontFamily: {
        sans: ["Inter", ...defaultTheme.fontFamily.sans],
        mono: ["Fira Code", "JetBrains Mono", ...defaultTheme.fontFamily.mono],
      },
      borderRadius: {
        none: "0",
        sm: "4px", // Small inputs, tight components
        base: "6px", // Standard (cards, buttons, inputs)
        lg: "8px", // Larger cards, modals
        full: "9999px", // Pills, avatars, badges
      },
      boxShadow: {
        none: "none",
        sm: "0 1px 2px 0 rgba(0, 0, 0, 0.05)",
        base: "0 1px 3px 0 rgba(0, 0, 0, 0.1)",
        md: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
        lg: "0 10px 15px -3px rgba(0, 0, 0, 0.1)",
        xl: "0 20px 25px -5px rgba(0, 0, 0, 0.1)",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        scaleIn: {
          "0%": { opacity: "0", transform: "scale(0.95)" },
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
      },
      animation: {
        "fade-in": "fadeIn 200ms ease-out",
        "scale-in": "scaleIn 300ms ease-out",
        "slide-in": "slideIn 250ms ease-out",
        "slide-in-right": "slideInRight 250ms ease-out",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
```

## CSS Variables (Update src/index.css)

Add these CSS variables for theme support:

```css
/* Light mode (default) */
:root {
  --border: 210 40% 74%;
  --input: 210 40% 96%;
  --ring: 224 100% 50%;
  --background: 0 0% 100%;
  --foreground: 210 40% 6%;
  
  --primary: 224 100% 50%;
  --primary-foreground: 0 0% 100%;
  
  --secondary: 210 40% 96%;
  --secondary-foreground: 210 40% 6%;
  
  --destructive: 0 100% 53%;
  --destructive-foreground: 0 0% 100%;
  
  --muted: 210 40% 96%;
  --muted-foreground: 210 40% 51%;
  
  --accent: 224 100% 50%;
  --accent-foreground: 0 0% 100%;
  
  --popover: 0 0% 100%;
  --popover-foreground: 210 40% 6%;
  
  --card: 0 0% 100%;
  --card-foreground: 210 40% 6%;
}

/* Dark mode (preferred) */
[data-theme="dark"],
[class~="dark"] {
  --border: 210 40% 20%;
  --input: 210 40% 20%;
  --ring: 224 100% 50%;
  --background: 210 40% 6%;
  --foreground: 210 40% 96%;
  
  --primary: 224 100% 50%;
  --primary-foreground: 0 0% 100%;
  
  --secondary: 210 40% 20%;
  --secondary-foreground: 210 40% 96%;
  
  --destructive: 0 100% 53%;
  --destructive-foreground: 210 40% 6%;
  
  --muted: 210 40% 20%;
  --muted-foreground: 210 40% 74%;
  
  --accent: 224 100% 50%;
  --accent-foreground: 0 0% 100%;
  
  --popover: 210 40% 20%;
  --popover-foreground: 210 40% 96%;
  
  --card: 210 40% 10%;
  --card-foreground: 210 40% 96%;
}
```

## Utility Classes for Common Patterns

Create `src/lib/classNames.ts`:

```typescript
/**
 * Pre-composed Tailwind class combinations for consistency
 * Use these instead of repeating long class strings
 */

export const buttonClasses = {
  // Base button styles
  base: "inline-flex items-center justify-center rounded-base font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  
  // Size variants
  sizes: {
    lg: "h-12 px-4 text-lg",
    md: "h-10 px-4 text-base",
    sm: "h-8 px-3 text-sm",
    xs: "h-7 px-2 text-xs",
  },
  
  // Color variants
  variants: {
    primary: "bg-primary text-primary-foreground hover:bg-primary-600 active:bg-primary-700",
    secondary: "border border-gray-300 bg-transparent text-foreground hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-900",
    destructive: "bg-error text-error-foreground hover:bg-error-600 active:bg-error-700",
    ghost: "text-foreground hover:bg-gray-100 dark:hover:bg-gray-800",
  },
};

export const inputClasses = {
  base: "flex h-10 w-full rounded-base border border-gray-300 bg-background px-3 py-2 text-base placeholder:text-gray-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700",
};

export const cardClasses = {
  base: "rounded-lg border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900",
  highlighted: "rounded-lg border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900 border-t-2 border-t-primary",
};

export const badgeClasses = {
  base: "inline-flex items-center rounded-full text-sm font-medium",
  sizes: {
    lg: "px-3 py-1",
    sm: "px-2 py-0.5",
  },
  variants: {
    primary: "bg-primary-100 text-primary-700 dark:bg-primary-900 dark:text-primary-100",
    success: "bg-success-100 text-success-700 dark:bg-success-900 dark:text-success-100",
    alert: "bg-alert-100 text-alert-700 dark:bg-alert-900 dark:text-alert-100",
    error: "bg-error-100 text-error-700 dark:bg-error-900 dark:text-error-100",
    gray: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
  },
};

export const containerClasses = {
  // Standard page container with padding
  page: "mx-auto max-w-7xl px-4 sm:px-6 lg:px-8",
  
  // Compact container for modals/focused content
  compact: "mx-auto max-w-md",
  
  // Full width with controlled content max-width
  full: "w-full",
};
```

## Component Usage Examples

### Button Component
```tsx
import { buttonClasses } from "@/lib/classNames";

export function Button({ 
  variant = "primary", 
  size = "md", 
  ...props 
}: {
  variant?: "primary" | "secondary" | "destructive" | "ghost";
  size?: "lg" | "md" | "sm" | "xs";
  [key: string]: any;
}) {
  const classes = [
    buttonClasses.base,
    buttonClasses.sizes[size],
    buttonClasses.variants[variant],
  ].join(" ");

  return <button className={classes} {...props} />;
}
```

### Card Component
```tsx
import { cardClasses } from "@/lib/classNames";

export function Card({ 
  highlighted = false, 
  className = "", 
  ...props 
}: {
  highlighted?: boolean;
  className?: string;
  [key: string]: any;
}) {
  const baseClass = highlighted ? cardClasses.highlighted : cardClasses.base;
  return <div className={`${baseClass} ${className}`} {...props} />;
}
```

## Migration Checklist

When updating existing components to match the design system:

- [ ] Replace all custom colors with design system colors
- [ ] Update spacing to 8px multiples only
- [ ] Change button styles to new variants
- [ ] Update input field styling
- [ ] Verify border-radius consistency (4px, 6px, 8px only)
- [ ] Remove any box-shadows except those in system
- [ ] Check font sizes against type scale
- [ ] Verify hover/active states on interactive elements
- [ ] Remove gradients and glow effects
- [ ] Test dark mode on all pages
- [ ] Check color contrast ratios (≥4.5:1)

## Performance Notes

- Inter font: Use variable font subset only (Latin)
- Icons: Lucide React ships with tree-shaking (unused icons removed)
- Animations: Use Tailwind's animation utilities (CSS-based, 60fps)
- Shadows: Only use for depth, not decoration
- Borders: Single 1px for clarity

## Testing Theme Changes

To test light/dark mode locally:

```typescript
// In your React app root
const [theme, setTheme] = useState("dark");

return (
  <div className={theme === "dark" ? "dark" : ""}>
    {/* Your app */}
  </div>
);
```

Or use next-themes (already in dependencies):

```typescript
import { ThemeProvider } from "next-themes";

<ThemeProvider attribute="class" defaultTheme="dark">
  {/* Your app */}
</ThemeProvider>
```
