# NexaBot Design System - Implementation Roadmap

## Phase 1: Foundation (Days 1-3)

### Goals
- Update Tailwind configuration with new design tokens
- Create base utilities and helper classes
- Establish dark mode support
- Test color palette

### Tasks

#### 1.1 Update Tailwind Configuration
- [ ] Copy new `tailwind.config.ts` from `TAILWIND_TOKENS.md`
- [ ] Verify all colors load correctly
- [ ] Test spacing scale (8px multiples)
- [ ] Verify type scale renders correctly
- [ ] Test border radius values

#### 1.2 Update CSS Variables (src/index.css)
- [ ] Add light mode CSS variables
- [ ] Add dark mode CSS variables
- [ ] Test theme switching
- [ ] Verify contrast ratios in both modes

#### 1.3 Create Token Utility Classes
- [ ] Create `src/lib/classNames.ts` with button, input, card, badge classes
- [ ] Test that classes work across all components
- [ ] Document usage patterns
- [ ] Create example components

#### 1.4 Font Setup
- [ ] Verify Inter font is installed (should be in package.json)
- [ ] Verify Fira Code or JetBrains Mono for mono
- [ ] Test font rendering at all sizes
- [ ] Verify no FOUT (flash of unstyled text)

#### 1.5 Verification
- [ ] Test light mode rendering
- [ ] Test dark mode rendering
- [ ] Check color contrast (minimum 4.5:1)
- [ ] Verify spacing grid consistency
- [ ] Check all typography sizes

**Deliverable**: `tailwind.config.ts` + `src/index.css` + `src/lib/classNames.ts` ready for use

---

## Phase 2: Component Updates (Days 4-7)

### Goals
- Update core reusable components to match design system
- Standardize button, input, card, modal styles
- Implement focus/hover/active states
- Test accessibility

### Components to Update (Priority Order)

#### High Priority (Shipping Blockers)
- [ ] Button component (all variants)
- [ ] Input / Form fields
- [ ] Card component
- [ ] Modal / Dialog
- [ ] Navigation (header + sidebar)

#### Medium Priority
- [ ] Badge component
- [ ] Badge component
- [ ] Dropdown / Popover
- [ ] Tabs
- [ ] Alerts / Toast notifications

#### Lower Priority
- [ ] Skeleton screens
- [ ] Progress indicators
- [ ] Pagination
- [ ] Breadcrumbs

### Testing Checklist Per Component
- [ ] Visual matches design system
- [ ] Dark mode works
- [ ] All states work (hover, focus, active, disabled)
- [ ] Keyboard navigation works
- [ ] Touch targets ≥44px
- [ ] Color contrast ≥4.5:1
- [ ] No console errors

**Deliverable**: Updated shadcn components following design system patterns

---

## Phase 3: Page-by-Page Migration (Days 8-14)

### Pages to Update (In Order)

#### First Wave (Most Critical)
1. **Landing Page** (`src/pages/Index.tsx`)
   - Update hero with new typography
   - Update color palette
   - Verify form styling
   - Test responsive layout

2. **Dashboard** (`src/pages/Dashboard.tsx`)
   - Update sidebar navigation
   - Update bot cards
   - Update stats display
   - Verify layout spacing

3. **Auth Pages** (Signup, Login, Verify Email)
   - Update form styling
   - Update button styles
   - Verify error messages

#### Second Wave
4. **Bot Configuration** (all bot settings pages)
5. **Conversations** (list + detail views)
6. **Analytics** (dashboard + charts)
7. **Settings** (all account pages)
8. **Billing** (payment, invoices, Web3 integration)

#### Third Wave
9. Supporting pages (About, Pricing, Blog, Docs, etc.)
10. Legal pages (Privacy, Terms, GDPR, etc.)

### Per-Page Checklist
- [ ] Heading hierarchy correct
- [ ] Spacing uses 8px grid
- [ ] Colors from palette only
- [ ] Typography follows scale
- [ ] Interactive elements styled
- [ ] Dark mode functional
- [ ] Mobile responsive
- [ ] Accessibility verified
- [ ] No visual regressions

**Deliverable**: All pages visually consistent with design system

---

## Phase 4: Feature-Specific Implementation (Ongoing)

### Dashboard Components
- [ ] Bot card (status, stats, actions)
- [ ] Recent activity timeline
- [ ] Quick action buttons
- [ ] Create bot flow

### Bot Configuration
- [ ] Training data uploader
- [ ] Integration setup cards
- [ ] Settings form sections
- [ ] Status indicators

### Conversations
- [ ] Conversation list with filters
- [ ] Search bar with clear states
- [ ] Conversation detail view
- [ ] Message thread styling
- [ ] Action buttons (resolve, delete, etc.)

### Analytics
- [ ] Metric cards
- [ ] Chart wrappers (Recharts)
- [ ] No-data state
- [ ] Date range picker
- [ ] Export button

### Billing
- [ ] Plan selector
- [ ] Invoice table
- [ ] Payment method cards
- [ ] Crypto payment option (subtle)
- [ ] Usage meter

### Web3 Integration
- [ ] Payment method selector (optional crypto)
- [ ] LitVM/zkLTC option display
- [ ] Transaction status indicator
- [ ] Settings footer reference

**Deliverable**: Feature-specific components styled and tested

---

## Phase 5: Polish & Optimization (Days 15+)

### Microinteractions
- [ ] Button click feedback
- [ ] Form submission feedback
- [ ] Page transitions
- [ ] Modal open/close animation
- [ ] Loading indicators
- [ ] Error animations

### Performance
- [ ] Measure LCP (First Contentful Paint)
- [ ] Measure CLS (Cumulative Layout Shift)
- [ ] Measure FID (First Input Delay)
- [ ] Optimize images (WebP + fallback)
- [ ] Verify bundle size (<150kb gzipped)
- [ ] Test on 3G network
- [ ] Check Lighthouse scores

### Accessibility Audit
- [ ] Run axe DevTools on all pages
- [ ] Verify keyboard navigation
- [ ] Test with screen reader
- [ ] Verify focus indicators
- [ ] Check color contrast
- [ ] Test form validation
- [ ] Verify motion preferences respected

### Cross-Browser Testing
- [ ] Chrome (latest)
- [ ] Firefox (latest)
- [ ] Safari (latest)
- [ ] Edge (latest)
- [ ] Mobile browsers

### Testing Checklist
- [ ] Light mode rendering
- [ ] Dark mode rendering
- [ ] Print styles (if needed)
- [ ] Hover states (desktop)
- [ ] Focus states (keyboard)
- [ ] Disabled states
- [ ] Loading states
- [ ] Error states
- [ ] Empty states

**Deliverable**: Polished, accessible, performant product

---

## Implementation Notes

### Git Workflow
```bash
# Create feature branch per phase
git checkout -b feat/design-system-foundation
git checkout -b feat/component-updates
git checkout -b feat/page-migration

# Commit frequently with clear messages
git commit -m "style: update Button component to design system"
```

### Testing Strategy
- **Visual Regression**: Use browser DevTools visual comparison
- **Accessibility**: axe DevTools, WAVE, lighthouse
- **Performance**: Lighthouse, WebPageTest
- **Responsive**: Chrome DevTools device emulation

### Communication
- Update team on progress daily
- Flag blockers immediately
- Get design review on critical components
- Document decisions in commit messages

### Rollout Strategy
1. **Week 1**: Foundation + core components
2. **Week 2**: Page migration (high priority)
3. **Week 3**: Feature components + second wave pages
4. **Week 4**: Polish + optimization + launch

### Approval Criteria

Before declaring phase complete:

#### Phase 1
- [ ] All design tokens load without errors
- [ ] Colors render correctly in both modes
- [ ] Typography scale displays properly
- [ ] Tailwind utilities available

#### Phase 2
- [ ] All core components updated
- [ ] States work (hover, focus, active, disabled)
- [ ] Dark mode functional
- [ ] Accessibility verified

#### Phase 3
- [ ] All pages updated
- [ ] No visual regressions
- [ ] Responsive design works
- [ ] Dark mode throughout

#### Phase 4
- [ ] Feature-specific components complete
- [ ] Web3 integration subtle and functional
- [ ] Data displays accurate
- [ ] Forms validate correctly

#### Phase 5
- [ ] Lighthouse score >90
- [ ] No accessibility violations
- [ ] Animation 60fps
- [ ] Bundle size <150kb gzipped
- [ ] Product ready to ship

---

## Quick Start Checklist

### For Developers Joining the Project
- [ ] Read `DESIGN_SYSTEM.md` (sections 1-5)
- [ ] Review `DESIGN_QUICK_REF.md` (bookmark it)
- [ ] Study `TAILWIND_TOKENS.md`
- [ ] Pull new `tailwind.config.ts`
- [ ] Test dark mode toggle
- [ ] Build a sample component using new tokens
- [ ] Ask questions before deviating from system

### For Designers Reviewing Work
- [ ] Use color picker to verify colors match palette
- [ ] Measure spacing with DevTools (should be 8px multiples)
- [ ] Check dark mode implementation
- [ ] Verify focus states visible
- [ ] Test keyboard navigation
- [ ] Check mobile responsive
- [ ] Verify contrast ratios
- [ ] Compare to DESIGN_SYSTEM.md

---

## Known Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| Color not matching exactly | Use HSL values from config, not hex |
| Spacing looks off | Always use 8px multiples, check Tailwind applied |
| Dark mode incomplete | Add `dark:` classes to all bg/text colors |
| Focus visible hidden | Never use `outline: none` without ring alternative |
| Mobile too cramped | Use responsive classes `md:`, `lg:` to adjust layout |
| Button too large | Use size variants (sm, md, lg) consistently |
| Text hard to read | Check contrast ratio, minimum 12px font |
| Animation janky | Use CSS animations, not JS transforms |

---

## Dependencies & Tools

**Already Installed:**
- React 19 + TypeScript
- Vite (build)
- Tailwind CSS 3
- shadcn/ui (Radix UI)
- Framer Motion (animations)
- Recharts (charts)
- Lucide React (icons)
- React Hook Form + Zod (forms)
- React Router v7 (routing)
- Supabase (auth)

**No Additional Installs Needed** - All tools required are already in dependencies.

---

## Success Metrics

By end of Phase 5, the product should have:

✅ **Visual Consistency**
- All colors from palette
- All spacing 8px multiples
- Typography strictly follows scale
- Borders 1px only
- Border radius 4px, 6px, 8px max

✅ **Functionality**
- All interactive elements have states
- Forms validate visibly
- Errors are specific and helpful
- Loading states shown
- Empty states helpful

✅ **Accessibility**
- Color contrast ≥4.5:1
- Focus visible everywhere
- Keyboard navigable
- Forms have labels
- No color-only information

✅ **Performance**
- LCP <2s
- CLS <0.1
- FID <100ms
- JS <150kb gzipped
- Lighthouse >90

✅ **Looks Like Real Product**
- No AI-generated aesthetics
- No template patterns
- Intentional, human-made feel
- Professional but not corporate
- Modern but not trendy

---

## Questions & Support

When stuck:
1. Check `DESIGN_QUICK_REF.md` first
2. Review relevant section in `DESIGN_SYSTEM.md`
3. Look at similar working component
4. Check `TAILWIND_TOKENS.md` for implementation examples
5. Ask team or file issue

---

**Last Updated**: 2025-05-12  
**Next Review**: After Phase 1 completion
