# NexaBot Component Blueprints

**Visual reference for component design. Shows exact structure, spacing, and styling.**

---

## BUTTONS

### Primary Button
```
┌─────────────────────┐
│    Create Bot       │  ← Text: 14px/base, white
└─────────────────────┘

Background: #0F6FFF (primary-500)
Padding: 16px horizontal, 10px vertical (py-2.5 px-4)
Height: 40px
Border-radius: 6px
Font: Inter 600 weight
Hover: #0F6FFF → 5% brighter
Active: #0F6FFF → 5% darker
Transition: 100ms ease-out

Focus state: Ring 2px around button in primary color
Disabled: 50% opacity, no pointer
```

### Secondary Button
```
┌─────────────────────┐
│      Cancel         │  ← Text: 14px/base, #0A0E27
└─────────────────────┘

Background: transparent
Border: 1px solid #D1D5DB (border-gray-300)
Padding: 16px horizontal, 10px vertical
Height: 40px
Border-radius: 6px
Hover: Light gray background (#F3F4F6)
Dark mode: Border #374151, hover #1F2937
```

### Destructive Button (Delete)
```
┌─────────────────────┐
│      Delete         │  ← Text: 14px/base, white
└─────────────────────┘

Background: #EF4444 (error-500)
Padding: 16px horizontal, 10px vertical
Height: 40px
Border-radius: 6px
Hover: Slightly darker red
Only used for: Delete, Reset, Clear actions
```

### Ghost Button
```
┌─────────────────────┐
│    Learn More       │  ← Text: 14px/base, #0F6FFF
└─────────────────────┘

Background: transparent
Border: none
Padding: 16px horizontal, 10px vertical
Hover: Underline appears + slight background
Used for: Secondary actions, links within sections
```

---

## INPUT FIELDS

### Default Input
```
┌──────────────────────────────┐
│ Enter bot name...            │  ← Placeholder: gray-500
└──────────────────────────────┘

Height: 40px
Padding: 10px 12px (vertical/horizontal)
Border: 1px solid #D1D5DB (gray-300)
Border-radius: 6px
Font: 14px Inter regular
Background: white
Focus: Ring 2px primary-500, border transparent
Transition: 150ms ease-out
Dark mode: bg-gray-800, border-gray-700
```

### Input with Label
```
Bot name
┌──────────────────────────────┐
│ Enter bot name...            │
└──────────────────────────────┘
* Required field                 ← Helper text, gray-500, 12px

Label: 14px/base, 600 weight, gap 8px above field
Helper text: 12px, optional below field
Error text: Replace helper, 12px, error-500 color
```

### Textarea (Multi-line)
```
Bot description
┌──────────────────────────────┐
│ Tell us about your bot...    │
│                              │
│                              │
└──────────────────────────────┘

Min height: 120px (160px preferred)
Resize handle: Bottom-right corner visible
Font: 14px mono for code input
Padding: 12px
Border: Same as input
Max width: 600px typical
```

### Select Dropdown
```
Choose platform ▼
┌──────────────────────────────┐
│ Select an option... ▼        │  ← Chevron icon right-aligned
└──────────────────────────────┘

Height: 40px
Padding: 12px 16px (text) + 40px (chevron space)
Icon: Chevron 20px, gray-600
Hover: Border becomes primary-500
Dark mode: Gray background, light text
Focus ring: Same as input
```

### Search Input
```
┌─────────────────────────────┐
│ Search conversations... ✕   │  ← 'x' clears field
└─────────────────────────────┘

Similar to default input
Icon (search): Left side, gray-500
Clear icon: Right side, appears on type
Placeholder: "Search conversations..."
```

---

## CARDS

### Bot Status Card
```
┌──────────────────────────────────────┐
│ My Support Bot               Active   │  ← Status badge
│                                      │
│ 32 conversations today               │  ← Metric, 12px gray
│ Last active: 2 hours ago             │  ← Timestamp, 12px gray
│                                      │
│ [Messenger] [WhatsApp] [Web]        │  ← Integration badges
│                                      │
│ [View] [Settings]                   │  ← Action buttons (hover)
└──────────────────────────────────────┘

Background: white / dark:gray-900
Border: 1px gray-200 / dark:gray-800
Padding: 20px (md spacing = 24px)
Border-radius: 8px
Title: 16px/base 600 weight
Status badge: Top-right corner
Metrics: Small text (12px), gray color
Integrations: Horizontal layout, icon badges
Actions: Appear on hover, right-aligned
```

### Highlighted Card (Active)
```
┌──────────────────────────────────────┐  ← Border-top 2px primary-500
│ Primary Bot                  Active   │
│                                      │
│ [content...]                         │
└──────────────────────────────────────┘

Same as default card, but:
- Add border-top: 2px solid #0F6FFF
- Indicates: Currently selected, high priority
- Light shadow to suggest depth
```

### Empty State Card
```
┌──────────────────────────────────────┐
│                                      │
│            ◌ (icon center)           │  ← Icon: 48px, gray-400
│                                      │
│      No conversations yet             │  ← Headline: 16px center
│                                      │
│    Your bot is deployed and          │
│    ready. Conversations will         │  ← Subheading: 14px gray
│    appear here.                      │
│                                      │
│         [Deploy Bot]                 │  ← CTA button
│                                      │
└──────────────────────────────────────┘
```

---

## BADGES (STATUS LABELS)

### Success Badge
```
┌─────────────┐
│  Active     │  ← Text: 12px, #10B981 dark color
└─────────────┘

Background: #D1FAE5 (success-100) / dark:#065F46 (success-900 bg)
Text color: #059669 (success-700) / dark:#10B981 (success-100)
Padding: 4px 12px
Border-radius: 999px (pill-shaped)
Font weight: 500
Icon: Optional checkmark (left-aligned)
```

### Alert Badge
```
┌──────────────┐
│  Processing  │
└──────────────┘

Background: #FEF3C7 (alert-100) / dark:#78350F (alert-900)
Text color: #D97706 (alert-700) / dark:#FBBF24 (alert-100)
Padding: 4px 12px
```

### Error Badge
```
┌────────────┐
│  Failed    │
└────────────┘

Background: #FEE2E2 (error-100) / dark:#7F1D1D (error-900)
Text color: #DC2626 (error-700) / dark:#FCA5A5 (error-100)
Padding: 4px 12px
```

### Gray Badge
```
┌──────────────┐
│  Pending     │
└──────────────┘

Background: #F3F4F6 (gray-100) / dark:#374151 (gray-700)
Text color: #6B7280 (gray-600) / dark:#E5E7EB (gray-200)
Padding: 4px 12px
```

---

## MODALS / DIALOGS

### Confirmation Modal
```
┌─────────────────────────────────────────┐
│ Delete conversation?                 ×  │  ← Title 28px, close icon
├─────────────────────────────────────────┤
│                                         │
│ This action cannot be undone.           │  ← Body text, 14px
│ The conversation with Sarah will be     │
│ permanently deleted.                    │
│                                         │
│ [Cancel]                  [Delete]      │  ← Buttons right-aligned
│                                         │
└─────────────────────────────────────────┘

Overlay: Black background, 30% opacity
Dialog width: 500px max, responsive mobile
Position: Center of screen, vertically centered
Padding: 32px (lg spacing)
Title: 28px/h1, bold
Body: 14px/base, gray text
Buttons: Cancel (secondary) + Primary action (right side)
Close button: X icon top-right, gray-500
```

### Form Modal
```
┌──────────────────────────────────────┐
│ Create new bot                    ×  │
├──────────────────────────────────────┤
│                                      │
│ Bot name                             │
│ ┌──────────────────────────────────┐│
│ │ My Support Assistant             ││
│ └──────────────────────────────────┘│
│                                      │
│ Industry                             │
│ ┌──────────────────────────────────┐│
│ │ Select industry... ▼              ││
│ └──────────────────────────────────┘│
│                                      │
│                       [Cancel] [Save] │  ← Buttons right-aligned
│                                      │
└──────────────────────────────────────┘

Spacing: gap-md (24px) between fields
Field labels: 14px/base 600 weight
Submit button: Primary (blue)
Cancel button: Secondary (outline)
Form width: 500px max
```

---

## NAVIGATION

### Top Navigation Bar
```
┌────────────────────────────────────────────────────────┐
│ [Logo] [Features] [Pricing] [Docs] [Blog]  [Sign In] [Sign Up]
└────────────────────────────────────────────────────────┘

Height: 64px
Padding: 16px 32px
Logo: 32px height (icon only, no text)
Nav links: Center, 16px spacing between
Auth buttons: Right-aligned
- Sign In: Text only (14px)
- Sign Up: Primary button
Background: Match page background (not separated)
Sticky on scroll
```

### Sidebar Navigation (App)
```
[Logo]

Chatbots
├─ [○] Create New Bot        ← Icon + label, 44px height
├─ [○] All Bots              ← Current active, primary blue bg
└─ [○] Templates

Analytics
├─ [○] Dashboard
└─ [○] Reports

Settings
├─ [○] Account
├─ [○] Billing
└─ [○] Team

Account
├─ [○] Profile
└─ [○] Sign Out

Width: 240px fixed (desktop)
Item height: 44px (tap-friendly)
Icon size: 20px
Font: 14px
Active item: Primary blue background, white text
Hover: Slightly darker background
Collapsible on mobile
```

---

## FORMS

### Contact Form (Multi-field)
```
Contact Us
─────────────────────────────

Email address
┌──────────────────────────┐
│ you@example.com          │
└──────────────────────────┘

Subject
┌──────────────────────────┐
│ I need help with...      │
└──────────────────────────┘

Message
┌──────────────────────────┐
│ Tell us more...          │
│                          │
│                          │
└──────────────────────────┘

[Clear]                [Send]

Spacing: 24px (md) between fields
Label: 14px 600 weight, gray-900
Input: 40px height, same styling
Textarea: 120px min height
Buttons: Right-aligned, Secondary + Primary
Responsive: Stack all fields on mobile
```

### Settings Form
```
Account Settings
─────────────────────────────────────

Personal Information

Full Name
┌──────────────────────────┐
│ Jane Doe                 │
└──────────────────────────┘

Email
┌──────────────────────────┐
│ jane@company.com         │
└──────────────────────────┘

Notifications
─────────────────────────────────────

[×] Email notifications
    Get updates about your bots

[✓] Message alerts
    Get notified of conversations

[✓] Weekly digest
    Summary of bot performance

                        [Save Changes]

Sections: Grouped with gray dividers
Checkboxes: Custom styled, 20px
Toggle text: 14px, description 12px gray
Save button: Primary, bottom-right
```

---

## CONVERSATION INTERFACE

### Conversation List
```
Search: [Search conversations...      ✕]

Filter: [Status ▼] [Platform ▼] [Date ▼]

Results: 47 conversations

┌─────────────────────────────────────────┐
│ [Avatar] Sarah H.          Pending      │  ← Status badge right
│ "Can you help me with my account?..." │  ← Message preview
│ 2 hours ago │ Messenger               │  ← Time, platform
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ [Avatar] John M.           Resolved     │
│ "Thanks, that solved my issue!" ...  │
│ 4 hours ago │ WhatsApp                 │
└─────────────────────────────────────────┘

Row height: 80px
Avatar: 40px circle, left
Name: 14px bold
Status: Badge top-right
Preview: 2 lines max, 14px
Metadata: 12px gray, bottom
Hover: Subtle background highlight
```

### Conversation Detail (Message Thread)
```
Sarah H.                    Pending  [Resolve] [Delete]
─────────────────────────────────────────────

2:34 PM
Sarah: Hi, I'm having trouble resetting my password.

2:35 PM
Bot: I can help with that! Let me guide you through
the password reset process...

2:38 PM
Sarah: That worked! Thanks so much.

2:39 PM
Bot: Great! Is there anything else I can help
with today?

─────────────────────────────────────────────
[Type a reply...] [Send]

Message styling:
- User messages: Right-aligned, light gray background
- Bot messages: Left-aligned, primary blue background
- Timestamp: 12px gray, above each message
- Time grouping: Show "2:34 PM" once per time
Thread height: ~500px, scrollable
Input: Bottom-fixed form, 40px
```

---

## DATA TABLES

### Conversations Analytics Table
```
Conversation Date      Platform    User      Status      Duration

2025-05-12  14:32  Messenger   Sarah H.    Resolved    3 min 45 sec
2025-05-12  13:15  WhatsApp    John M.     Resolved    1 min 20 sec
2025-05-12  12:42  Website     Alex P.     Pending     5 min
2025-05-12  11:28  Messenger   Emma R.     Resolved    2 min 10 sec

Row height: 44px
Header: Bold, gray background (#F3F4F6)
Padding: 16px columns
Borders: 1px bottom between rows only
Hover: Subtle background highlight
Striped: Optional alternate row color
Responsive: Horizontal scroll on mobile
```

---

## STATUS & FEEDBACK

### Loading State (Spinner)
```
           ⟲          ← Animated rotation
       Training bot...

Spinner: 24px, primary-500
Text: 14px, gray-600
Duration: Infinite, smooth rotation
Position: Centered on page / in button
```

### Error Message
```
┌─────────────────────────────┐
│ ✕ Failed to save settings   │  ← Icon + title
│                             │
│ Your connection was lost.   │  ← Description
│ Please check and try again. │
│                             │
│        [Retry]              │  ← Action button
└─────────────────────────────┘

Background: #FEE2E2 (error-100) / dark:#7F1D1D
Border-left: 3px solid #EF4444
Padding: 16px
Icon: 20px, error-500
Title: 14px bold
Description: 14px, regular
Button: Small primary button
Position: Toast bottom-right OR inline
```

### Success Confirmation
```
┌─────────────────────────────┐
│ ✓ Bot trained successfully! │
│                             │
│ Your chatbot is ready to    │
│ deploy to your website.     │
│                             │
│        [Deploy]             │
└─────────────────────────────┘

Background: #D1FAE5 (success-100) / dark:#065F46
Border-left: 3px solid #10B981
Icon: ✓ checkmark, success-600
Title: 14px bold
Description: 14px regular, success-600
Duration: 4s auto-dismiss
```

---

## EMPTY STATES

### No Data Empty State
```
           ◌
        (icon)

      No conversations yet

Your bot is deployed and ready
to receive messages. It will appear here.

         [View Bot Setup]

Icon: 48px, gray-400
Headline: 16px bold, center
Description: 14px gray, center, 2-3 lines
Action: Primary button, optional
```

### Search No Results
```
           ◌
      (search icon)

   No conversations found

Try adjusting your filters or search term.

[Clear Filters]

Icon: Search icon, gray-400
Similar layout to no data
Clear button instead of generic action
```

---

## FORM VALIDATION

### Success State
```
Email
┌──────────────────────────────┐
│ jane@company.com        ✓    │  ← Checkmark green
└──────────────────────────────┘
✓ Email looks good!            ← Helper text green

Border: Gray (default)
Helper text: success-500 color, 12px
Icon: Checkmark right-aligned
```

### Error State
```
Email
┌──────────────────────────────┐
│ invalid.email          ✕     │  ← X red
└──────────────────────────────┘
✕ Please enter valid email      ← Error text red

Border: error-500 color
Helper text: error-500, 12px
Icon: X mark right-aligned
Focus ring: error color instead of primary
```

---

## RESPONSIVE BEHAVIOR

### Mobile Sidebar (Hidden)
```
Mobile viewport:

[☰] NexaBot              [⚙️]
─────────────────────────────
[Main content...]

☰ Menu icon: Toggle sidebar drawer
Sidebar: Full-height drawer from left
Content: Full width when sidebar open
```

### Card Grid (Responsive)
```
Desktop (3 columns):     │ Tablet (2 columns):    │ Mobile (1 column):
┌─────┬─────┬─────┐    │ ┌────────┬────────┐  │ ┌──────────┐
│ A   │ B   │ C   │    │ │ A      │ B      │  │ │ A        │
├─────┼─────┼─────┤    │ ├────────┼────────┤  │ ├──────────┤
│ D   │ E   │ F   │    │ │ C      │ D      │  │ │ B        │
└─────┴─────┴─────┘    │ ├────────┼────────┤  │ ├──────────┤
                       │ │ E      │ F      │  │ │ C        │
                       │ └────────┴────────┘  │ └──────────┘
```

---

## SPACING MEASUREMENTS

### Typical Page Layout
```
┌────────────────────────────────────────────┐
│    Header (fixed, 64px height)             │
├──────┬────────────────────────────────────┤
│      │                                    │
│ Nav  │ padding: lg (32px)                │
│      │                                    │
│ 240px│ ┌──────────────────────────────┐  │
│      │ │ Page Title                   │  │
│      │ │                              │  │
│      │ │ gap: md (24px)               │  │
│      │ │                              │  │
│      │ │ ┌─────────────┬─────────────┐│  │
│      │ │ │ Card 1      │ Card 2      ││  │
│      │ │ │             │             ││  │
│      │ │ │ gap: md     │ gap: md     ││  │
│      │ │ │             │             ││  │
│      │ │ └─────────────┴─────────────┘│  │
│      │ │                              │  │
│      │ │ gap: lg (32px)               │  │
│      │ │                              │  │
│      │ │ ┌──────────────────────────┐ │  │
│      │ │ │ Section                  │ │  │
│      │ │ │                          │ │  │
│      │ │ └──────────────────────────┘ │  │
│      │ │                              │  │
│      │ └──────────────────────────────┘  │
│      │                                    │
└──────┴────────────────────────────────────┘
```

---

## ANIMATION TIMINGS

### Page Transition (Fade In)
```
Duration: 200ms
Easing: ease-out
Curve: Smooth, not bouncy
Used on: Route changes
```

### Modal Open (Scale In)
```
Start state: opacity 0, scale 0.95
End state: opacity 1, scale 1.0
Duration: 300ms
Easing: ease-out
```

### Loading Spinner
```
Duration: 2s per rotation
Infinite loop
Color: primary-500 (#0F6FFF)
Size: 24px typical
```

---

**Last Updated**: 2025-05-12
