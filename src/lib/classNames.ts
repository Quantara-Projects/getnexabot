/**
 * Pre-composed Tailwind class combinations for consistency
 * Use these instead of repeating long class strings
 */

export const buttonClasses = {
  base: "inline-flex items-center justify-center rounded-base font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  sizes: {
    lg: "h-12 px-4 text-lg",
    md: "h-10 px-4 text-base",
    sm: "h-8 px-3 text-sm",
    xs: "h-7 px-2 text-xs",
  },
  variants: {
    primary: "bg-primary text-primary-foreground hover:bg-primary-600 active:bg-primary-700",
    secondary: "border border-gray-300 bg-transparent text-foreground hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-900",
    destructive: "bg-error text-white hover:bg-error-600 active:bg-error-700",
    ghost: "text-foreground hover:bg-gray-100 dark:hover:bg-gray-800",
  },
};

export const inputClasses = {
  base: "flex h-10 w-full rounded-base border border-gray-300 bg-background px-3 py-2 text-base placeholder:text-gray-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 dark:border-gray-700",
};

export const cardClasses = {
  base: "rounded-lg border border-gray-200 bg-card",
  highlighted: "rounded-lg border border-gray-200 bg-card border-t-2 border-t-primary",
};

export const badgeClasses = {
  base: "inline-flex items-center rounded-full text-sm font-medium",
  sizes: {
    lg: "px-3 py-1",
    sm: "px-2 py-0.5",
  },
  variants: {
    primary: "bg-primary/10 text-primary-700 dark:bg-primary/20 dark:text-primary-100",
    success: "bg-success/10 text-success-700 dark:bg-success/20 dark:text-success-100",
    alert: "bg-alert/10 text-alert-700 dark:bg-alert/20 dark:text-alert-100",
    error: "bg-error/10 text-error-700 dark:bg-error/20 dark:text-error-100",
    gray: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
  },
};

export const containerClasses = {
  page: "mx-auto max-w-7xl px-4 sm:px-6 lg:px-8",
  compact: "mx-auto max-w-md",
  full: "w-full",
};
