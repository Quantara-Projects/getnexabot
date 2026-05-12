# NexaBot Design System
## Production-Grade UI/UX Specification

---

## 1. CORE DESIGN PHILOSOPHY

### What Makes This Real
NexaBot is positioned as a **professional automation platform**, not a "flashy" crypto app. The interface must communicate:
- **Reliability**: This handles customer conversations. Trust is non-negotiable.
- **Speed**: Setup should feel fast. Data should load instantly.
- **Control**: Users own their chatbot configuration. No black boxes.
- **Accessibility**: Non-technical users deploy it. Clarity over complexity.

### Design Principles (Priority Order)
1. **Information Hierarchy Over Decoration** - Every pixel serves a function
2. **Consistency Over Uniqueness** - Predictable patterns reduce cognitive load
3. **Speed Over Aesthetics** - Fast feedback beats beautiful delays
4. **Trust Over Excitement** - Calm, professional energy
5. **Clarity Over Cleverness** - Label everything plainly

### Visual Identity Archetype
Think: Intercom + Stripe + Linear (not Figma, not Framer)
- Professional but not corporate-stiff
- Modern without trying too hard
- Dark-mode native (crypto audience habit)
- Minimal ornamentation

---

## 2. COLOR SYSTEM

### Core Palette (Structured, Not Random)

#### Primary Colors
- **Primary Brand: `#0F6FFF`** (Electric Blue)
  - Trustworthy, energetic, technical
  - Used for: CTAs, active states, data highlights
  - Not neon, not dull—active but not aggressive

- **Neutral Dark: `#0A0E27`** (Deep Navy)
  - Default background (dark mode native)
  - High contrast with text
  - Feels professional, not cold

- **Neutral Light: `#F8F9FB`** (Off-white)
  - Secondary background
  - Subtle, not pure white (reduces eye strain)

#### Supporting Colors
- **Success: `#10B981`** (Teal)
  - Conversations delivered
  - Leads captured
  - Tests passing
  - Naturalistic, not lime

- **Alert: `#F59E0B`** (Amber)
  - Rate limits approaching
  - Manual review needed
  - Training in progress
  - Warm, not screaming

- **Error: `#EF4444`** (Red)
  - Failures, deletions, rejections
  - Minimal use (only actual problems)
  - Not pink, not orange—clean red

- **Muted: `#6B7280`** (Gray)
  - Secondary text
  - Disabled states
  - Borders
  - No purple-gray (too design-trendy)

#### Web3 Context (Subtle, Not Dominant)
- **Crypto Accent: `#8B5CF6`** (Purple)
  - Only in: Payment methods, blockchain status, LitVM mentions
  - Never in primary navigation or hero
  - Single-use, not scattered

### Psychology & Usage
- **Blue (Primary)**: Associated with reliability, communication, tech
- **Teal (Success)**: Natural growth and health
- **Amber (Alert)**: Attention without alarm
- **Purple (Crypto)**: Only where Web3 features exist
- **No gradients, no glow, no transparency-stacking**

### Dark Mode Default, Light Mode Support
- Dark mode: Primary background `#0A0E27`, text `#F8F9FB`
- Light mode: Primary background `#FFFFFF`, text `#0A0E27`
- Theme toggle in footer (not header—keeps focus on content)

---

## 3. TYPOGRAPHY SYSTEM

### Font Stack
```
Primary: Inter, system-ui, -apple-system
(Industry standard, not generic "sans-serif")

Mono: Fira Code or JetBrains Mono
(For API endpoints, code snippets, webhooks)
```

### Why Inter?
- Designed for screens (not print)
- Exceptional at small sizes (UI labels)
- Neutral personality (doesn't distract)
- Web3 space standard (Uniswap, Mirror, Lido use it)

### Type Scale

#### Display (Hero/Page Titles)
- **Display 1**: 48px / 56px line-height / weight 700
  - Main hero headline
  - Marketing pages only

- **Display 2**: 36px / 44px line-height / weight 600
  - Section headlines
  - Dashboard page titles

#### Interface
- **Heading 1**: 28px / 36px line-height / weight 600
  - Major section headers
  - Modal titles

- **Heading 2**: 20px / 28px line-height / weight 600
  - Card titles, subsection headers

- **Heading 3**: 16px / 24px line-height / weight 600
  - Labels, small headers

#### Body
- **Body Large**: 16px / 24px line-height / weight 400
  - Primary body copy, CTA text
  - Default reading text

- **Body Regular**: 14px / 22px line-height / weight 400
  - Secondary body text, tooltips, descriptions
  - Most UI label text

- **Body Small**: 12px / 18px line-height / weight 400
  - Metadata, timestamps, helper text
  - Never below 12px (accessibility)

#### Mono (Code/Technical)
- **Mono Large**: 14px / 20px line-height / weight 500
  - API endpoint displays
  - Webhook URLs

- **Mono Regular**: 12px / 18px line-height / weight 400
  - Code blocks, tokens, IDs
  - Train data preview

### Hierarchy Rules
- Never use more than 4 type sizes on one screen
- Weight only varies: 400 (normal), 500 (medium—labels), 600 (semi-bold—headings), 700 (bold—marketing)
- Avoid weight 300 (too thin) and 800+ (too aggressive)
- Line-height always ≥ 1.5 for accessibility

---

## 4. SPACING & LAYOUT SYSTEM

### The 8px Grid (Hard Baseline)
All spacing, sizes, and positioning use multiples of 8:
```
8px, 16px, 24px, 32px, 48px, 64px, 96px, 128px
```

### Standard Spacing (No Random Padding)
- **Compact (xs)**: 8px (internal component gaps)
- **Small (sm)**: 16px (padding within cards)
- **Medium (md)**: 24px (spacing between sections)
- **Large (lg)**: 32px (main section gaps)
- **Huge (xl)**: 48px+ (full-width section breaks)

### Container Width & Margins
```
Max-width: 1280px (matches Tailwind lg breakpoint)
Side margins: 32px (desktop), 16px (tablet), 16px (mobile)
Gap between columns: 24px
```

### Layout Principles
- **No centered content blocks** (feels less actionable)
- **Left-aligned primary content** (natural reading direction)
- **Sidebar for settings/options** (keeps main flow clean)
- **Cards for grouping** (clear visual boundaries)

### Breakpoints (Actual Usage)
```
Mobile: 320px–639px (base)
Tablet: 640px–1023px (medium adjustments)
Desktop: 1024px+ (full system)
Wide: 1280px+ (maximum content width)
```

---

## 5. COMPONENT SYSTEM (Custom Variants)

### Button Component
**Purpose**: All interactive actions (sign up, send, configure, etc.)

#### States
- **Primary** (Blue): Main actions (Send message, Create bot)
- **Secondary** (Gray outline): Alternative actions (Cancel, Reset)
- **Destructive** (Red): Deletions, resets (Delete conversation, Clear logs)
- **Ghost** (No fill): Tertiary or text-like buttons (View more, Learn more)

#### Sizes
- **Large**: 48px height, 16px padding (primary CTAs)
- **Medium**: 40px height, 14px padding (standard use)
- **Small**: 32px height, 12px padding (table actions, secondary)
- **Xs**: 28px height, 10px padding (icon buttons only)

#### No Shadows, Subtle Borders
```
Default: Solid background, no drop shadow
Hover: 2% brightness increase (not color shift)
Active: 5% brightness decrease
Disabled: 50% opacity, no pointer
```

### Input / Form Fields
**Purpose**: Data entry for bot training, settings, configuration

#### Base Style
- Height: 40px (16px padding top/bottom)
- Border: 1px solid `#334155` (slate-700 dark)
- Border-radius: 6px (modern, not sharp)
- Font: Body Regular (14px)
- Placeholder: Gray muted text

#### States
- **Default**: Border in muted color
- **Focus**: Border in primary blue, subtle glow removed (stroke only)
- **Error**: Border in red, optional error message below
- **Disabled**: Light background, 50% opacity

#### Special Inputs
- **Select dropdown**: Chevron icon right-aligned, arrow indicates direction
- **Textarea**: 120px min-height, resize handle visible
- **Checkbox/Radio**: Custom SVG icons (not browser defaults)
- **Sliders**: Thumb styled as pill button, track clear

### Card Component
**Purpose**: Content grouping (conversations, bot stats, integrations)

#### Base Style
- Background: Slightly lighter than page background (`#111832` in dark)
- Border: 1px solid `#1E293B` (subtle divider)
- Padding: 16px standard, 24px for large cards
- Border-radius: 8px
- No shadows (clean, flat design)
- Optional: Top border accent (2px in primary color)

#### Variants
- **Default**: Neutral card, no special treatment
- **Highlighted**: Primary color top border (active bot, high priority)
- **Muted**: Disabled or secondary information
- **Interactive**: Hover darkens slightly, cursor pointer

### Badge Component
**Purpose**: Labels, status indicators, tags

#### Uses
- **Status**: "Active", "Training", "Offline"
- **Tags**: "Messenger integration", "Lead capture"
- **Counts**: Conversation count, unread badge

#### Color Options
- Blue (primary)
- Green (success/active)
- Amber (warning/processing)
- Red (error/offline)
- Gray (neutral/inactive)

#### Size
- **Large**: 24px height, 8px horizontal padding (prominent labels)
- **Small**: 18px height, 6px horizontal padding (tags, counts)

### Data Display (Tables, Lists)
**Purpose**: Bot conversations, analytics, user activity logs

#### Table Structure
- Row height: 44px (enough space, not wasted)
- Column padding: 16px left/right
- Header: Bold text, gray background `#1E293B`
- Striped rows: Alternate light shades for clarity
- No full-width borders (too heavy)—column dividers only

#### Inline Actions
- Actions grouped right-aligned (edit, delete, view)
- Use icon buttons (smaller footprint)
- Tooltip on hover (explains action)

### Modal/Dialog
**Purpose**: Confirmations, workflows, detailed editing

#### Behavior
- Overlay: Dark semi-transparent (not heavy blur)
- Dialog: Centered, max-width 500px (standard)
- Padding: 32px (breathing room)
- Close button: Top-right corner (X icon)
- Buttons: Primary action right, secondary left

#### Content
- Heading: Display 2 size (28px)
- Body: Body Regular (14px)
- No more than 3 actions per dialog
- Default focus on primary action

### Sidebar Navigation
**Purpose**: Main app navigation when logged in

#### Structure
- **Fixed left sidebar**: 240px width (desktop), collapsible (mobile)
- **Items**: Icon + Label, 44px height
- **Active state**: Primary color background, white text
- **Hover**: Subtle background change
- **Sections**: Group related items (Chatbots, Analytics, Settings, Account)
- **Logo**: Top of sidebar, 48px height

#### Sections
```
1. Primary Actions
   - Create New Bot
   - Conversations

2. Navigation
   - Chatbots (list all)
   - Analytics
   - Integrations

3. Settings
   - Account
   - Billing
   - Team

4. Account
   - Profile
   - Sign Out
```

### Top Navigation (Marketing Pages)
**Purpose**: Branding, links, auth entry point

#### Layout
- **Max-width container**: 1280px, centered
- **Logo + Links**: Left-aligned logo, center navigation, right auth buttons
- **Sticky**: Stays at top on scroll
- **Background**: Matches page background (not separated)
- **Height**: 64px

#### Content
- Logo: 32px height, no text (icon only)
- Nav links: 5 max (Home, Pricing, Features, Docs, Blog)
- Auth buttons: Sign In (text), Sign Up (primary button)
- Mobile: Hamburger menu, full-height drawer

### Notification/Toast System
**Purpose**: Feedback for actions (saved, error, sync complete)

#### Behavior
- **Position**: Bottom-right (doesn't block main content)
- **Duration**: 4 seconds (auto-dismiss)
- **Max stack**: 3 visible (older ones fade)
- **Size**: 340px max-width

#### Variants
- **Success**: Green badge, checkmark icon
- **Error**: Red badge, X icon
- **Info**: Blue badge, info icon
- **Warning**: Amber badge, alert icon

#### Content
- **Title**: Bold, short (1 line)
- **Description**: Optional, small text (2 lines max)
- **Action**: Optional secondary button (Undo, Retry, View)
- **Close**: X button always available

---

## 6. SPECIFIC LAYOUTS & FLOWS

### Dashboard (Main App Page)
**Goal**: Overview of bot status, quick actions, recent activity

#### Layout Grid
```
┌─────────────────────────────────────┐
│ Header: "Chatbots" + Create Button  │
├─────────────────────────────────────┤
│ [Sidebar] │ Main Content            │
│           │                         │
│           │ ┌─ Bot Cards Grid ───┐  │
│           │ │ (2-3 columns)      │  │
│           │ │ - Status           │  │
│           │ │ - Conversations    │  │
│           │ │ - Last Active      │  │
│           │ │ - Quick Actions    │  │
│           │ └────────────────────┘  │
│           │                         │
│           │ ┌─ Recent Activity ───┐ │
│           │ │ Timeline format     │ │
│           │ │ (conversations log) │ │
│           │ └────────────────────┘ │
└─────────────────────────────────────┘
```

#### Bot Card Details
- **Title**: Bot name (bold)
- **Status**: Badge (Active/Offline/Training)
- **Stat line**: "32 conversations today"
- **Last active**: "2 hours ago"
- **Integration badges**: Show connected platforms (Messenger, WhatsApp, etc.)
- **Action buttons**: View, Edit, Settings (hover-revealed)

### Bot Configuration Page
**Goal**: Set up and customize individual chatbot

#### Two-Column Layout
```
Left Sidebar (240px fixed):
- Basic info
- Training data
- Integrations
- Settings
- Analytics

Right Content (fluid):
- Forms, editors, previews
- Change based on sidebar selection
```

#### Training Data Section
- **Drag-drop area**: "Upload FAQ, docs, or paste content"
- **Preview**: Shows parsed data, count of chunks
- **Edit inline**: Remove, re-train, test on sample
- **Status**: Shows training progress (bar or spinner)

#### Integration Setup
- **Cards for each platform**: Messenger, WhatsApp, Slack, Discord, Web Widget
- **Connected state**: Green badge + disconnect button
- **Setup state**: Gray card + setup button (opens guide)
- **Config needed**: Shows required fields (API key, webhook, etc.)

### Conversations View
**Goal**: Browse, search, and review customer interactions

#### List with Filter Bar
```
Top bar:
[Search box] [Filter: Status] [Filter: Date] [Sort: Newest]

Results:
- Conversation row layout
  - Avatar + User name
  - Message preview (2 lines max)
  - Status badge (Resolved/Pending)
  - Bot used
  - Date/time
  - [View button]
```

#### Conversation Detail (Modal or Slide-out)
- **Header**: User name, status, bot used
- **Message thread**: Timeline of exchanges
  - User messages: Right-aligned, light background
  - Bot messages: Left-aligned, primary color
  - Timestamps: Gray, small text
- **Actions**: Mark resolved, reassign, delete
- **Notes section**: Add internal notes (not visible to user)

### Analytics Dashboard
**Goal**: Show bot performance, engagement, conversion

#### Key Metrics (Top Row)
```
Card grid (4 columns, responsive):
- Total Conversations
- Lead Capture Rate
- Resolution Rate
- Average Response Time
```

#### Visualization Section
- **Conversations over time**: Line chart, last 30 days
- **Platform breakdown**: Pie chart (where conversations come from)
- **Common topics**: Bar chart (what users ask about)
- **Lead quality**: Table (captured emails, submission rates)

#### No Fake Data
- Show real ranges based on actual usage
- Empty state: "No data yet. Come back after first conversation."

### Settings Page
**Goal**: Account, billing, team, Web3 payment config

#### Left Navigation + Content
```
Settings sections:
1. Profile
   - Avatar, name, email
   - Change password

2. Billing
   - Current plan
   - Usage metrics
   - Invoice history
   - Web3 payment methods (subsection)

3. Team
   - Invite members
   - Role management
   - Audit log

4. API & Webhooks
   - API keys (generate, revoke)
   - Webhook setup (URLs, events)

5. Danger Zone
   - Delete account
   - Export data
```

#### Billing Section Detail
- **Plan tier**: Show current + upgrade option
- **Usage meter**: Conversations used / limit
- **Invoice list**: Recent transactions (fiat + crypto)
- **Web3 section**: "Pay with LitVM or zkLTC" (optional, not forced)

### Sign Up / Login Flow
**Goal**: Frictionless authentication, no friction

#### Sign Up Page
```
Left side (50%):
- Headline: "Run AI support, instantly"
- Subheading: "No coding required"
- 3 benefits bullets
- Illustration: Chat interaction visual

Right side (50%):
- Form: Email, password
- CTA: "Create account"
- "Have an account?" link to login
```

#### Login Page (Simpler)
```
Centered form (400px max):
- Headline: "Welcome back"
- Email input
- Password input
- "Forgot password?" link
- "Sign in" button (primary)
- Divider
- "Create account" link
```

#### Verification Email
- Simple confirmation flow
- OTP input if 2FA enabled
- Resend link if needed

---

## 7. INTERACTION & MICROINTERACTION DESIGN

### Click Feedback
```
Button press:
1. Immediate visual response (no 200ms delay)
2. 3px opacity decrease (not color shift)
3. Subtle shadow increase (depth feeling)
4. 100ms ease-out transition
5. Return to normal on release
```

### Hover States (Desktop Only)
```
Button:
- 5% brightness increase
- Cursor becomes pointer
- Transition: 150ms

Link:
- Underline appears
- Color shifts slightly
- Transition: 150ms

Card (interactive):
- Border changes to primary color
- Slight scale up (1.02)
- Cursor becomes pointer
```

### Loading States
- **Button loading**: Text hidden, spinner inside button (same size)
- **Page loading**: Skeleton layout matches final content structure
- **Data refresh**: Small spinner in top-right corner, doesn't block interaction
- **Training progress**: Bar with percentage, animated fill

### Transitions & Motion
- **Page transitions**: Fade in (200ms) when route changes
- **Modal open**: Scale up from center (300ms, ease-out)
- **Modal close**: Scale down (200ms, ease-in)
- **Sidebar toggle**: Slide in/out (250ms)
- **Dropdown/popover**: Fade + scale (150ms)

### Do NOT:
- Bounce animations
- Stagger effects on lists (slows perception)
- Parallax scrolling
- Auto-play animations
- Fade backgrounds (use opacity only for overlays)

---

## 8. MEDIA SYSTEM (Images, Video, Icons)

### Custom Icons (Lucide React Native Style)
All icons use the existing `lucide-react` library, modified for consistency:

**Icon Weight**: 1.5px stroke (not too thin, not too thick)
**Icon Size Variants**:
- 16px: UI labels, compact spaces
- 20px: Buttons, most common use
- 24px: Sidebar nav, card headers
- 32px: Page titles, hero sections
- 48px: Feature cards, illustrations

**Color**:
- Default: Match text color (inherit)
- Interactive: Primary blue on hover
- Disabled: Gray, 50% opacity

**Custom Icons Needed** (in addition to Lucide):
- Bot head (AI assistant icon)
- Conversation bubbles (chat)
- Integration nodes (network/web)
- Data flow (arrows, connections)
- Training cycle (loop/refresh)

### Photography & Illustrations

#### Product Screenshots
- **Live product**: Real conversation interface
- **Integration setup**: Actual config screens
- **Dashboard**: Real analytics (anonymized data)
- **No stock photos**: Shows actual UI in use

#### Abstract Visuals (Where Needed)
**Purpose**: Hero sections, feature cards—only 3-4 total

1. **Conversation Flow**: Minimalist SVG showing message exchange
   - Two nodes connected by lines
   - Message indicators (circles moving along lines)
   - 2-3 colors (blue, accent)
   - Looping animation (subtle)

2. **Integration Network**: Nodes and connections
   - Center node (bot), surrounding platforms
   - Connection lines light up as integrations add
   - SVG-based, minimal style

3. **Data Training Visual**: Parallel lines with data moving through
   - Represents learning/processing
   - Animated flow lines
   - Blue primary color

4. **Speed/Performance**: Horizontal bars getting faster
   - Represents quick setup and fast responses
   - Animated bars decreasing in length
   - Green accent

**Key Rules**:
- SVG-based (not raster)
- 2-3 colors max per visual
- Animated but not distracting (opacity fade, motion)
- Specific to NexaBot (not generic icons)
- Serve a functional purpose (explain value)

### Video Integration (Minimal)

#### Where Video Works
1. **Hero Background**: Subtle chat flow animation (10s loop)
   - Real conversation happening
   - Chat bubbles appearing/disappearing
   - No sound, no controls
   - Muted by default

2. **Feature Demos**: 15-20 second snippets in expandable cards
   - "See WhatsApp integration in action"
   - Shows quick demo of platform connection
   - Play button overlay
   - Auto-pause when out of view

3. **Onboarding**: Short walkthrough (30s max per step)
   - First time setup
   - How to add training data
   - How to configure integrations

**Video Specs**:
- Format: MP4 (H.264)
- Bitrate: 5-8 Mbps (balance quality vs speed)
- No background music (distraction)
- Auto-play muted (no sound on auto-play)
- Loop: True for backgrounds, False for demos
- Poster frame: Static image backup

### Web3 Visual Elements
**Where crypto/blockchain appears:**
- Wallet connection modal: Small LitVM/zkLTC logos
- Payment method selector: Crypto option with icon
- Transaction status: Blockchain confirmation indicator
- Settings > Billing: LitVM chain reference (footer note, not prominent)

**Style**:
- Minimal, use existing logos (don't customize)
- Never in hero or main content
- Always paired with traditional payment option
- Gray color (secondary, not emphasized)

---

## 9. ACCESSIBILITY & PERFORMANCE

### Color Contrast
- **Text on background**: Minimum 4.5:1 ratio (WCAG AA)
- **Interactive elements**: Minimum 3:1 ratio
- **Not relying on color alone** (always add text/icon)

### Interactive Targets
- **Minimum size**: 44px × 44px (mobile, WCAG standard)
- **Minimum spacing**: 8px between targets
- **Focus indicators**: Always visible (not removed with CSS)
- **Keyboard navigation**: Tab order logical, Enter/Space trigger actions

### Motion & Vestibular
- **Respect prefers-reduced-motion**: Remove animations if enabled
- **No auto-playing video**: User controls all motion
- **No strobing**: Keep animations below 3Hz

### Responsive Design
- **Mobile-first approach**: Design for 320px, then enhance
- **Touch-friendly**: Buttons ≥44px, spacing ≥8px
- **Font size**: Never below 16px on mobile (prevents zoom)
- **Viewport**: `<meta name="viewport" content="width=device-width, initial-scale=1">`

### Performance
- **Images**: Optimized, WebP with fallback
- **Icons**: SVG only (instant, scalable)
- **Fonts**: 2 files max (Inter + Mono), variable font
- **Animations**: Use CSS, not JavaScript (60fps)
- **Code splitting**: Pages load separate bundles
- **Lazy loading**: Images below fold, video elements

---

## 10. NAVIGATION ARCHITECTURE

### User Journey (Key Flows)

#### Marketing Site Visitor
```
Landing → Features → Pricing → Sign Up → Verify Email → Dashboard
```

#### New User (First Time)
```
Dashboard → Create Bot → Train with Data → Add Integration → Test → Deploy
```

#### Active User (Daily Usage)
```
Dashboard → Select Bot → Conversations → Review & Respond → Analytics
```

#### Account Settings
```
Dashboard → Settings → Choose Section → Edit → Save
```

### URL Structure
```
/                          - Landing page
/pricing                   - Pricing page
/docs                      - API documentation
/blog                      - Blog/updates
/sign-up                   - Registration
/login                     - Sign in
/verify-email              - Email verification
/dashboard                 - Main app (logged in)
/bot/:botId                - Single bot config
/bot/:botId/conversations  - Conversation list
/bot/:botId/analytics      - Bot analytics
/settings/profile          - Account settings
/settings/billing          - Billing & payments
/settings/api-keys         - Developer settings
/404                       - Not found
```

---

## 11. FORM & DATA ENTRY PATTERNS

### Bot Creation Form
**Steps**:
1. Basic info (name, industry)
2. Training data (upload or paste)
3. Integrations (choose platforms)
4. Review & deploy

**Not a wizard**: Single page with sections, not modal steps

### Training Data Input
```
Three input methods:
1. File upload (PDF, DOCX, TXT)
2. Paste text directly (FAQ, docs)
3. URL crawl (website scraper)

Results:
- Show parsed chunks
- Edit/remove individual pieces
- Training status indicator
```

### Integration Setup
```
Each integration:
- Requirements checklist
- Credential input fields
- Test connection button
- Success/error messaging
- Instructions link
```

### Search & Filter
**Conversations list**:
```
Top bar with:
- Search by user name / message
- Filter by status (Resolved, Pending, etc.)
- Filter by platform (Messenger, WhatsApp, etc.)
- Sort by date (Newest, Oldest, Unread)
- Clear all filters button
```

**Always show**:
- Number of results
- No results state (helpful message + suggestion)
- Option to clear filters

---

## 12. ERROR HANDLING & EMPTY STATES

### Error Messages
**Pattern**: Icon + Title + Description + Action

```
Title: "Failed to save settings"
Description: "Your internet connection was interrupted. Please check your connection and try again."
Action: [Retry button]
```

**Not**:
- "Error 403"
- "Something went wrong"
- "Please check the form"

### Empty States
**Conversations (no chats yet)**:
```
Icon: Chat bubble illustration
Headline: "No conversations yet"
Subheading: "Deploy your bot to start receiving messages"
Action: [Deploy Bot button]
```

**Analytics (no data)**:
```
Icon: Chart icon
Headline: "Analytics coming soon"
Subheading: "Run your bot for a few hours to see performance data"
Action: [View Bot] or [Learn more]
```

**Search results (no matches)**:
```
Headline: "No conversations found"
Subheading: "Try adjusting your filters or search term"
[Clear Filters] button
```

### Loading States (Real, Not Fake)
- **Skeleton screens**: Match final layout exactly
- **Progress indicators**: Show actual progress (not fake bar)
- **Estimated time**: "Loading... (about 5s)" if known
- **Cancellable**: Allow users to stop long operations

---

## 13. WEB3 & PAYMENT INTEGRATION (Subtle, Not Forced)

### Guiding Principle
Web3 features are **opt-in extras**, not core product identity.

### Where Crypto Appears
1. **Billing Section**
   - Primary: Traditional payment (credit card)
   - Secondary: Crypto option (LitVM, zkLTC)
   - Label: "Pay with cryptocurrency (optional)"

2. **Payment Method Selector**
   - Card payment (default selected)
   - LitVM payment option
   - zkLTC payment option
   - Clear explanations of pros/cons

3. **Transaction Status**
   - If crypto: Show blockchain confirmation status
   - Link to block explorer (for verification)
   - Still simple: "Confirmed" or "Pending"

4. **Settings Footer**
   - Small note: "Built on LitVM Ecosystem"
   - Not in header or hero
   - Trust signal only

### What NOT to Do
- Crypto jargon in main UI (No "smart contracts", "gas fees")
- Crypto first, fiat second (wrong priority)
- Forced Web3 onboarding
- Crypto token mentions in hero/main nav
- Web3 buzzwords in marketing copy

### Design Implementation
```
Billing Page Example:

Current Plan: Starter ($29/month)

Payment Method:
- Credit/Debit Card (selected)
  └─ [Edit] [Remove]
- Add payment method [+]

Optional: Pay with Crypto
"Save with cryptocurrency payments"
- LitVM (10% discount)
- zkLTC (10% discount)
[Learn more about crypto payments]

Invoices:
[Recent invoices table—both fiat and crypto shown]
```

---

## 14. IMPLEMENTATION DIRECTION

### Tech Stack (Already Committed)
- **Framework**: React 19 + TypeScript
- **Styling**: Tailwind CSS (no raw CSS)
- **UI Components**: Shadcn/ui (Radix UI primitives)
- **Animation**: Framer Motion (already dependency)
- **Charts**: Recharts (already dependency)
- **Icons**: Lucide React (already dependency)
- **Forms**: React Hook Form + Zod validation
- **State**: React Context or TanStack Query (already set up)
- **Routing**: React Router v7 (already set up)
- **Auth**: Supabase (already integrated)

### Component Organization
```
src/components/
├── ui/                          (Shadcn primitives—minimal changes)
├── Shared/
│   ├── Navigation.tsx           (Top nav for all pages)
│   ├── Sidebar.tsx              (Left nav for app)
│   ├── Footer.tsx
│   └── Toast/Notifications.tsx
├── Dashboard/
│   ├── BotCardGrid.tsx
│   ├── RecentActivity.tsx
│   └── DashboardStats.tsx
├── Bot/
│   ├── BotConfigSidebar.tsx
│   ├── TrainingDataSection.tsx
│   ├── IntegrationSetup.tsx
│   └── BotSettings.tsx
├── Conversations/
│   ├── ConversationList.tsx
│   ├── ConversationDetail.tsx
│   └── ConversationSearch.tsx
├── Analytics/
│   ├── MetricsCard.tsx
│   ├── Charts.tsx               (Recharts wrappers)
│   └── AnalyticsDashboard.tsx
├── Billing/
│   ├── PlanSelector.tsx
│   ├── PaymentMethodCard.tsx
│   ├── CryptoPaymentOption.tsx
│   └── InvoiceList.tsx
└── Auth/
    ├── SignupForm.tsx
    ├── LoginForm.tsx
    └── EmailVerification.tsx
```

### Naming Conventions
- **Components**: PascalCase, descriptive (not `Card1`, `Card2`)
- **Files**: Match component name exactly
- **Utilities**: camelCase, verb-first (formatDate, validateEmail)
- **Types**: PascalCase with `I` prefix (IBot, IConversation) OR no prefix
- **Constants**: UPPER_SNAKE_CASE
- **Classes/Variants**: camelCase with modifier (buttonPrimary, cardHighlighted)

### CSS/Tailwind Rules
- No custom CSS files (all in Tailwind)
- Custom colors in tailwind.config.ts (HSL variables)
- Reusable class combinations in component `className`
- Avoid `@apply` (prefer inline utilities)
- Breakpoints: `sm`, `md`, `lg`, `xl` (no custom names)

### Performance Budgets
- **JavaScript**: <150kb gzipped (bundle size)
- **First Contentful Paint**: <2s (on 3G)
- **Time to Interactive**: <4s
- **Lighthouse Score**: >90 (all categories)

---

## 15. DESIGN TOKENS & TAILWIND CONFIG

### Add to `tailwind.config.ts`

```typescript
// Color tokens (HSL format for flexibility)
colors: {
  // Primary
  primary: {
    '50': 'hsl(224 71% 96%)',
    '100': 'hsl(224 71% 90%)',
    '200': 'hsl(224 71% 80%)',
    '300': 'hsl(224 71% 70%)',
    '400': 'hsl(224 71% 55%)',
    '500': 'hsl(224 100% 50%)',   // #0F6FFF
    '600': 'hsl(224 100% 45%)',
    '700': 'hsl(224 100% 35%)',
    '800': 'hsl(224 100% 25%)',
    '900': 'hsl(224 100% 15%)',
  },
  // Success (teal)
  success: {
    '50': 'hsl(167 71% 93%)',
    '500': 'hsl(167 71% 45%)',    // #10B981
    '700': 'hsl(167 71% 25%)',
  },
  // Alert (amber)
  alert: {
    '50': 'hsl(39 100% 93%)',
    '500': 'hsl(39 100% 55%)',    // #F59E0B
    '700': 'hsl(39 100% 35%)',
  },
  // Error (red)
  error: {
    '50': 'hsl(0 100% 93%)',
    '500': 'hsl(0 100% 53%)',     // #EF4444
    '700': 'hsl(0 100% 33%)',
  },
  // Neutral grays
  gray: {
    '50': 'hsl(210 40% 96%)',     // Near white
    '100': 'hsl(210 40% 92%)',
    '200': 'hsl(210 40% 86%)',
    '300': 'hsl(210 40% 74%)',
    '400': 'hsl(210 40% 63%)',
    '500': 'hsl(210 40% 51%)',    // #6B7280
    '600': 'hsl(210 40% 42%)',
    '700': 'hsl(210 40% 33%)',    // #1E293B
    '800': 'hsl(210 40% 20%)',    // #111832
    '900': 'hsl(210 40% 6%)',     // #0A0E27
  },
  // Crypto (purple, used sparingly)
  crypto: {
    '500': 'hsl(258 71% 50%)',    // #8B5CF6
    '700': 'hsl(258 71% 35%)',
  },
},

// Extended spacing
spacing: {
  // 8px grid
  'xs': '0.5rem',    // 8px
  'sm': '1rem',      // 16px
  'md': '1.5rem',    // 24px
  'lg': '2rem',      // 32px
  'xl': '3rem',      // 48px
  '2xl': '4rem',     // 64px
  '3xl': '6rem',     // 96px
},

// Typography
fontSize: {
  'display-1': ['48px', { lineHeight: '56px', fontWeight: '700' }],
  'display-2': ['36px', { lineHeight: '44px', fontWeight: '600' }],
  'h1': ['28px', { lineHeight: '36px', fontWeight: '600' }],
  'h2': ['20px', { lineHeight: '28px', fontWeight: '600' }],
  'h3': ['16px', { lineHeight: '24px', fontWeight: '600' }],
  'lg': ['16px', { lineHeight: '24px', fontWeight: '400' }],
  'base': ['14px', { lineHeight: '22px', fontWeight: '400' }],
  'sm': ['12px', { lineHeight: '18px', fontWeight: '400' }],
  'mono-lg': ['14px', { lineHeight: '20px', fontWeight: '500' }],
  'mono': ['12px', { lineHeight: '18px', fontWeight: '400' }],
},

// Border radius
borderRadius: {
  'none': '0',
  'sm': '4px',       // Small buttons, tight components
  'base': '6px',     // Standard (inputs, cards)
  'lg': '8px',       // Larger cards, modals
  'full': '9999px',  // Pills, avatars
},

// Box shadow (minimal, functional only)
boxShadow: {
  'none': 'none',
  'sm': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
  'base': '0 1px 3px 0 rgba(0, 0, 0, 0.1)',
  'md': '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
  'lg': '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
  'xl': '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
},

// Animation (reduced, functional)
animation: {
  'fade-in': 'fadeIn 200ms ease-out',
  'scale-in': 'scaleIn 300ms ease-out',
  'slide-in': 'slideIn 250ms ease-out',
},

keyframes: {
  fadeIn: {
    from: { opacity: '0' },
    to: { opacity: '1' },
  },
  scaleIn: {
    from: { opacity: '0', transform: 'scale(0.95)' },
    to: { opacity: '1', transform: 'scale(1)' },
  },
  slideIn: {
    from: { transform: 'translateX(-100%)' },
    to: { transform: 'translateX(0)' },
  },
},
```

---

## 16. DESIGN CHECKLIST

Before shipping any feature:

### Visual
- [ ] Uses approved color palette only
- [ ] Typography follows scale exactly (no random sizes)
- [ ] Spacing is multiple of 8px
- [ ] Icons are consistent weight and size
- [ ] No gradients, glows, or shadows not approved
- [ ] Borders are 1px only (except focus states)
- [ ] Consistency with existing components

### Interaction
- [ ] Clickable elements ≥44px
- [ ] Focus visible (ring or outline)
- [ ] Hover/active states clear
- [ ] Loading states show real progress
- [ ] Errors are specific and actionable
- [ ] Empty states helpful, not sad

### Accessibility
- [ ] Color contrast ≥4.5:1 (AA standard)
- [ ] Keyboard navigable (Tab, Enter, Escape)
- [ ] Screen reader compatible (labels, aria attributes)
- [ ] Motion respects prefers-reduced-motion
- [ ] Form validation is clear

### Performance
- [ ] Page loads in <2s on 3G
- [ ] Interactions are responsive (<100ms)
- [ ] Images optimized and lazy-loaded
- [ ] No unnecessary animations
- [ ] Bundle size monitored

### Copy
- [ ] Labels are plain and concise
- [ ] No jargon or marketing fluff
- [ ] No emojis (none, ever)
- [ ] Consistent voice across all UI
- [ ] Error messages are helpful

---

## 17. SIGNATURE FEATURES & MEMORABLE UX

### 1. Conversation Preview Cards
When hovering over a conversation in the list, show a brief animated preview of the actual messages (not just metadata). Creates connection between list and detail view.

### 2. Training Data Chunks Visualization
Instead of just listing uploaded docs, show how the bot parsed them into chunks with a count. Visual representation: "1,247 knowledge chunks" with preview of actual chunks.

### 3. Integration Pulse
When integrations are active, show a subtle pulsing indicator. Indicates "live" status without being obnoxious.

### 4. One-Click Deployment
After bot is configured, a single "Deploy" button activates all selected integrations at once (not separate toggles). Celebrates successful setup with confirmation animation.

### 5. Conversation Sentiment Indicator
Quick visual (subtle color) on conversation cards showing if customer sentiment seems positive/negative (based on bot's assessment). Helps prioritize reviews.

### 6. Smart Empty States
Empty states aren't generic—they're contextual. "No conversations yet" when bot just deployed vs. "No conversations today" when looking at a specific date range.

### 7. Activity Timeline (Not Boring List)
Dashboard shows activity timeline instead of tables. Visual progression through the day, easier to scan.

---

## 18. WHAT NOT TO IMPLEMENT

- ❌ Parallax scrolling
- ❌ Hover animations that slow interaction
- ❌ Blur/transparency stacking
- ❌ Auto-playing background videos in main content
- ❌ Animated SVG illustrations that autoplay
- ❌ Gradient text or backgrounds
- ❌ 3D transforms
- ❌ Lottie animations (except small, functional ones)
- ❌ Rainbow color schemes
- ❌ Curved buttons or extreme border-radius
- ❌ Glass morphism or neumorphism effects
- ❌ Glow/shadow effects
- ❌ Skeleton screens that are overly animated
- ❌ Micro-interactions that distract (bounces, springs)

---

## 19. NEXT STEPS: IMPLEMENTATION PHASES

### Phase 1: Foundation (Week 1-2)
- [ ] Update tailwind.config.ts with new token system
- [ ] Create custom color CSS variables
- [ ] Build reusable component variants (Button, Input, Card, Badge)
- [ ] Set up type system in TypeScript
- [ ] Create color/spacing helper utilities

### Phase 2: Layouts (Week 2-3)
- [ ] Dashboard layout with sidebar
- [ ] Bot configuration pages
- [ ] Conversations list and detail views
- [ ] Settings page structure

### Phase 3: Integration (Week 3-4)
- [ ] Move existing pages to new design system
- [ ] Update Forms with new input styles
- [ ] Create modals and dialogs (sign up, create bot, etc.)
- [ ] Implement analytics dashboard

### Phase 4: Polish (Week 4+)
- [ ] Microinteractions and animations
- [ ] Accessibility audit and fixes
- [ ] Performance optimization
- [ ] Cross-browser testing
- [ ] Mobile responsive refinement

---

## 20. REFERENCE & INSPIRATION

**Companies with similar maturity level:**
- Intercom (professional, no-nonsense)
- Stripe (precise, trustworthy)
- Linear (clean, modern)
- Vercel (minimal, functional)
- Supabase (open, approachable)

**What to steal:**
- Stripe's form design (clarity, validation)
- Intercom's conversation UI (natural reading)
- Linear's command palette (efficiency)
- Vercel's onboarding (frictionless)
- Supabase's docs (walkthrough clarity)

---

## CONCLUSION

This design system is intentionally **boring, clear, and professional**. That's the point.

It's not trying to impress at a design conference. It's trying to help non-technical users set up a powerful AI chatbot in minutes, deploy it, and manage it effectively.

Every design decision serves a functional purpose. Every color, every spacing, every animation has a reason.

This is how real products feel when shipped by teams that care about shipping.

---

**Document Version**: 1.0  
**Last Updated**: 2025-05-12  
**Maintained By**: Product Design Team  
