# NexaBot UI Design - Quick Reference

**Use this guide daily when building new features. It's a one-page companion to the full design system.**

---

## COLOR PALETTE (Copy-paste ready)

### Primary Brand
- **Primary Blue**: `#0F6FFF` or `text-primary-500` (CTAs, highlights)
- **Dark BG**: `#0A0E27` or `bg-gray-900` (page backgrounds, dark mode)
- **Light BG**: `#F8F9FB` or `bg-gray-50` (secondary surfaces, light mode)

### Status Colors (Semantic)
- **Success**: `#10B981` or `text-success-500` (completed, active)
- **Alert**: `#F59E0B` or `text-alert-500` (processing, attention needed)
- **Error**: `#EF4444` or `text-error-500` (failed, rejected)
- **Muted**: `#6B7280` or `text-gray-500` (disabled, secondary)

### Web3 (Crypto, Subtle Only)
- **Purple Accent**: `#8B5CF6` or `text-crypto-500` (blockchain, payments ONLY)

---

## SPACING GRID (Always Use 8px Multiples)

```
8px  = xs
16px = sm
24px = md
32px = lg
48px = xl
64px = 2xl
96px = 3xl
```

**In Tailwind**: `p-xs`, `p-sm`, `p-md`, `gap-md`, etc.

**Example**: Card padding = `p-sm` (16px), section spacing = `gap-lg` (32px)

---

## TYPOGRAPHY SCALE

### Display (Marketing/Hero)
- **H1**: `text-display-1` (48px, bold) — Main hero headline
- **H2**: `text-display-2` (36px, semi-bold) — Section headers

### Headings (App/UI)
- **Heading 1**: `text-h1` (28px) — Page titles
- **Heading 2**: `text-h2` (20px) — Card titles
- **Heading 3**: `text-h3` (16px) — Labels

### Body Text
- **Large**: `text-lg` (16px) — Primary body copy
- **Regular**: `text-base` (14px) — Default UI text, labels
- **Small**: `text-sm` (12px) — Secondary, meta info

### Code/Technical
- **Mono Large**: `text-mono-lg` (14px) — API endpoints
- **Mono**: `text-mono` (12px) — Code blocks, tokens

**Rule**: Never go below 12px. Never use 5 different sizes on one screen.

---

## BORDER & RADIUS

**Borders**: Always `1px`, color from `border-gray-200` (light) or `border-gray-700` (dark)

**Border Radius**:
- `rounded-sm` = 4px (small buttons, tight components)
- `rounded-base` = 6px (inputs, cards, modals) — MOST COMMON
- `rounded-lg` = 8px (larger cards)
- `rounded-full` = pills, avatars

**Rules**:
- No extreme curves (≤8px max)
- No rounded corners on data tables
- Cards: `rounded-lg border border-gray-200 dark:border-gray-800`

---

## COMPONENTS QUICK REFERENCE

### Button
```tsx
// Primary (blue, main action)
<button className="px-4 py-2 bg-primary-500 text-white rounded-base hover:bg-primary-600">
  Action
</button>

// Secondary (outline)
<button className="px-4 py-2 border border-gray-300 rounded-base hover:bg-gray-50">
  Cancel
</button>

// Destructive (red, only delete/reset)
<button className="px-4 py-2 bg-error-500 text-white rounded-base">
  Delete
</button>

// Ghost (minimal, tertiary)
<button className="px-4 py-2 hover:bg-gray-100 rounded-base">
  Learn More
</button>
```

**Sizes**:
- `h-12 px-4` = Large (48px height)
- `h-10 px-4` = Medium (40px height) — DEFAULT
- `h-8 px-3` = Small (32px height)
- `h-7 px-2` = Tiny (28px, icons only)

### Input Fields
```tsx
<input 
  className="w-full h-10 px-3 rounded-base border border-gray-300 
             focus:ring-2 focus:ring-primary-500 focus:border-transparent
             dark:bg-gray-800 dark:border-gray-700"
  placeholder="Your text..."
/>
```

**Always include**:
- Height: `h-10` (40px)
- Padding: `px-3 py-2`
- Border: `border border-gray-300`
- Focus ring: `focus:ring-2 focus:ring-primary-500`
- Dark mode: `dark:border-gray-700`

### Cards
```tsx
<div className="rounded-lg border border-gray-200 bg-white p-sm dark:bg-gray-900 dark:border-gray-800">
  {/* Content */}
</div>
```

**Variants**:
- Add `border-t-2 border-t-primary` for highlighted state
- `shadow-sm` for slight depth (use sparingly)

### Badges (Status Labels)
```tsx
// Success
<span className="px-3 py-1 rounded-full text-sm bg-success-100 text-success-700 dark:bg-success-900 dark:text-success-100">
  Active
</span>

// Alert
<span className="px-3 py-1 rounded-full text-sm bg-alert-100 text-alert-700 dark:bg-alert-900 dark:text-alert-100">
  Processing
</span>

// Error
<span className="px-3 py-1 rounded-full text-sm bg-error-100 text-error-700 dark:bg-error-900 dark:text-error-100">
  Failed
</span>
```

### Modal/Dialog
```tsx
<div className="fixed inset-0 z-50 bg-black/30 flex items-center justify-center">
  <div className="bg-white dark:bg-gray-900 rounded-lg shadow-lg max-w-md w-full mx-4 p-lg">
    <h1 className="text-h1 mb-md">Title</h1>
    <p className="text-base text-gray-600 dark:text-gray-400 mb-lg">
      Description
    </p>
    <div className="flex gap-sm justify-end">
      <button className="px-4 py-2 border rounded-base">Cancel</button>
      <button className="px-4 py-2 bg-primary-500 text-white rounded-base">
        Confirm
      </button>
    </div>
  </div>
</div>
```

---

## INTERACTION STATES

### Hover (Desktop)
- Button: `5%` brightness increase, cursor pointer
- Link: Underline appears, slight color shift
- Card (interactive): Border becomes primary color, scale 1.02

### Focus (Keyboard)
- Always visible: `focus:ring-2 focus:ring-primary-500 focus:ring-offset-2`
- Works on buttons, inputs, links
- Never remove outline

### Active / Pressed
- Button: `3%` brightness decrease
- Duration: 100ms `ease-out`

### Disabled
- `opacity-50 pointer-events-none cursor-not-allowed`
- No hover state
- Gray text

### Loading
- Show spinner INSIDE button (same height)
- Text hidden
- Button stays same size

---

## DO's & DON'Ts

✅ DO:
- Use 8px spacing only
- Keep typography scale strict (4 sizes max)
- Add hover/focus states to interactive elements
- Use semantic colors (success, alert, error)
- Dark mode by default, support light
- Use Tailwind utilities (no raw CSS)
- Group related form fields
- Show loading & error states
- Write plain, clear labels

❌ DON'T:
- Mix colors randomly (use palette only)
- Add gradients, glows, or blur effects
- Use colors just for aesthetics
- Make shadows prominent
- Add animations that distract
- Use rounded corners >8px
- Use emojis (ever, anywhere)
- Create fake data
- Scatter design tokens across files
- Skip accessibility (focus, contrast)

---

## DARK MODE (Required)

Every component must work in both modes.

```tsx
// Right way:
<div className="bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-50">
  {/* Works in both modes */}
</div>

// Wrong:
<div className="bg-white">
  {/* Broken in dark mode */}
</div>
```

**Test with**: Add `dark` class to root element, toggle in DevTools

---

## FORM VALIDATION

### Error Display
```tsx
<div>
  <input className="border-error-500 focus:ring-error-500" />
  <p className="mt-1 text-sm text-error-500">This field is required</p>
</div>
```

### Success Display
```tsx
<div>
  <input className="border-success-500" />
  <p className="mt-1 text-sm text-success-500">Looks good!</p>
</div>
```

### Key Rules
- Show error below field
- Use `error-500` color
- Include helpful message (not just "Error")
- No red background (too aggressive)

---

## ACCESSIBILITY CHECKLIST

Before shipping any component:

- [ ] Color contrast ≥4.5:1 (use contrast checker)
- [ ] Focus visible on all interactive elements
- [ ] Keyboard navigable (Tab, Enter, Escape)
- [ ] Form inputs have labels
- [ ] Error messages specific, not generic
- [ ] Images have alt text
- [ ] Loading states shown
- [ ] Disabled state clear
- [ ] Touch targets ≥44px (mobile)

---

## COMMON LAYOUTS

### Page Layout (with Sidebar)
```tsx
<div className="flex h-screen">
  {/* Sidebar: 240px fixed */}
  <nav className="w-60 bg-white dark:bg-gray-900 border-r border-gray-200">
    {/* nav items */}
  </nav>
  
  {/* Main: Flex fill */}
  <main className="flex-1 overflow-auto">
    <div className="max-w-7xl mx-auto px-lg py-lg">
      {/* Page content */}
    </div>
  </main>
</div>
```

### Grid Layout (Cards)
```tsx
<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-lg">
  {/* Cards auto-fit */}
</div>
```

### Form Layout
```tsx
<form className="max-w-md mx-auto space-y-lg">
  <div>
    <label className="block text-base font-medium mb-sm">Label</label>
    <input className="w-full h-10 px-3 rounded-base border" />
  </div>
</form>
```

---

## ICON USAGE (Lucide React)

```tsx
import { MessageCircle, Settings, ChevronDown } from "lucide-react";

// Default: 20px, gray
<MessageCircle size={20} className="text-gray-600" />

// Accent: 24px, primary blue
<Settings size={24} className="text-primary-500" />

// Button icon: 16px
<ChevronDown size={16} />

// Sidebar nav: 24px, color on hover
<MessageCircle size={24} className="group-hover:text-primary-500" />
```

**Sizes**: 16 (small), 20 (default), 24 (medium), 32 (large)
**Colors**: Inherit text color, or override with Tailwind class

---

## ANIMATION (Keep It Minimal)

```tsx
import { motion } from "framer-motion";

// Fade in (200ms)
<motion.div
  initial={{ opacity: 0 }}
  animate={{ opacity: 1 }}
  transition={{ duration: 0.2 }}
>
  Content
</motion.div>

// Scale in (300ms)
<motion.div
  initial={{ opacity: 0, scale: 0.95 }}
  animate={{ opacity: 1, scale: 1 }}
  transition={{ duration: 0.3 }}
>
  Content
</motion.div>
```

**Rules**:
- Page transitions: `fade-in` (200ms)
- Modal open: `scale-in` (300ms)
- No bounce, no stagger, no parallax
- Respect `prefers-reduced-motion`

---

## RESPONSIVE BREAKPOINTS

```
Mobile:  320–639px   (default)
Tablet:  640–1023px  (md:)
Desktop: 1024px+     (lg:)
Wide:    1280px+     (max-w-7xl)
```

**Default mobile-first**: Design for mobile, enhance with `md:`, `lg:`

```tsx
<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
  {/* 1 column mobile, 2 tablet, 3 desktop */}
</div>
```

---

## PERFORMANCE

- **Images**: WebP + JPEG fallback, `lazy` loading below fold
- **Fonts**: Inter variable only (no bold/light separate files)
- **Bundle**: Keep JS <150kb gzipped
- **LCP**: <2s on 3G (prioritize CSS)
- **Animations**: CSS-based, 60fps (no janky JS)
- **Icons**: Lucide tree-shakes unused icons

---

## COMMON MISTAKES (AVOID)

❌ Wrong colors scattered everywhere  
❌ Spacing not 8px multiples  
❌ Font sizes between scale steps  
❌ No focus states on buttons  
❌ Buttons without hover feedback  
❌ Text not contrasted  
❌ Rounded corners >8px  
❌ Box shadows on every element  
❌ Inline styles instead of Tailwind  
❌ Skipping dark mode  

---

## DESIGN SYSTEM RESOURCES

- **Full Design System**: See `DESIGN_SYSTEM.md`
- **Tailwind Config**: See `TAILWIND_TOKENS.md`
- **Color Reference**: Use `primary-500`, `success-500`, etc. in all components
- **Type Scale**: 12px minimum, use preset sizes only

---

## GETTING UNSTUCK

| Problem | Solution |
|---------|----------|
| Color doesn't match | Check `tailwind.config.ts` colors, use `-500` variant |
| Spacing feels off | Use 8px multiples only: `gap-md`, `p-lg`, etc. |
| Text too small | Never below 12px (`text-sm`), check dark mode contrast |
| Button doesn't look right | Add focus ring: `focus:ring-2 focus:ring-primary` |
| Dark mode broken | Add `dark:bg-gray-900` class to backgrounds |
| Component too wide | Wrap in `max-w-7xl mx-auto` |
| Hover doesn't work | Add `hover:` state class, check element is interactive |
| Not matching design | Compare to DESIGN_SYSTEM.md sections 5 & 6 |

---

**Last Updated**: 2025-05-12  
**Version**: 1.0  
**For questions**: Refer to full DESIGN_SYSTEM.md or TAILWIND_TOKENS.md
