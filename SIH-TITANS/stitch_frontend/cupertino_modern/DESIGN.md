---
name: Cupertino Modern
colors:
  surface: '#faf9fe'
  surface-dim: '#dad9df'
  surface-bright: '#faf9fe'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f4f3f8'
  surface-container: '#eeedf3'
  surface-container-high: '#e9e7ed'
  surface-container-highest: '#e3e2e7'
  on-surface: '#1a1b1f'
  on-surface-variant: '#414755'
  inverse-surface: '#2f3034'
  inverse-on-surface: '#f1f0f5'
  outline: '#717786'
  outline-variant: '#c1c6d7'
  surface-tint: '#005bc1'
  primary: '#0058bc'
  on-primary: '#ffffff'
  primary-container: '#0070eb'
  on-primary-container: '#fefcff'
  inverse-primary: '#adc6ff'
  secondary: '#006e28'
  on-secondary: '#ffffff'
  secondary-container: '#6ffb85'
  on-secondary-container: '#00732a'
  tertiary: '#4c4aca'
  on-tertiary: '#ffffff'
  tertiary-container: '#6664e4'
  on-tertiary-container: '#fffbff'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#d8e2ff'
  primary-fixed-dim: '#adc6ff'
  on-primary-fixed: '#001a41'
  on-primary-fixed-variant: '#004493'
  secondary-fixed: '#72fe88'
  secondary-fixed-dim: '#53e16f'
  on-secondary-fixed: '#002107'
  on-secondary-fixed-variant: '#00531c'
  tertiary-fixed: '#e2dfff'
  tertiary-fixed-dim: '#c2c1ff'
  on-tertiary-fixed: '#0c006a'
  on-tertiary-fixed-variant: '#3631b4'
  background: '#faf9fe'
  on-background: '#1a1b1f'
  surface-variant: '#e3e2e7'
typography:
  display:
    fontFamily: Geist
    fontSize: 48px
    fontWeight: '700'
    lineHeight: '1.1'
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: -0.01em
  headline-lg-mobile:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: '1.2'
  headline-md:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: '1.3'
  body-lg:
    fontFamily: Geist
    fontSize: 17px
    fontWeight: '400'
    lineHeight: '1.5'
  body-md:
    fontFamily: Geist
    fontSize: 15px
    fontWeight: '400'
    lineHeight: '1.4'
  label-md:
    fontFamily: Geist
    fontSize: 13px
    fontWeight: '500'
    lineHeight: '1.2'
    letterSpacing: 0.01em
  label-sm:
    fontFamily: Geist
    fontSize: 11px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: 0.03em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  unit: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  xxl: 48px
  gutter: 20px
  margin-mobile: 16px
  margin-desktop: 40px
---

## Brand & Style

This design system embodies a premium, software-centric aesthetic characterized by clarity, precision, and depth. It targets professional users who value efficiency and high-end craftsmanship. The emotional response is one of calm reliability and sophisticated simplicity.

The design style is a hybrid of **Minimalism** and **Glassmorphism**. It prioritizes vast amounts of negative space (white space) to reduce cognitive load, while using translucent, frosted layers to provide spatial context and hierarchy. Every element feels intentional, secondary to the content it holds, following the philosophy that the interface should recede to let user data shine.

## Colors

The palette is rooted in the high-contrast "Cupertino" tradition. 

- **Primary (#007AFF):** Used for interactive elements, primary actions, and selection states.
- **Success (#34C759):** Reserved for positive confirmations and "go" signals.
- **Surface Variant (#F5F5F7):** A soft, neutral gray used for background grouping, secondary containers, and sidebar fills to distinguish them from the pure white primary canvas.
- **System Accents:** Vibrant system colors should be used sparingly against white backgrounds to maintain professional legibility.

Avoid using heavy fills for secondary items; prefer subtle grays or transparent tints of the primary color for hover states.

## Typography

This design system uses **Geist** for its technical precision and systematic feel, mimicking the legibility of SF Pro. 

Key principles:
- **Tight Tracking:** Larger headlines use slightly negative letter spacing to feel more cohesive.
- **Optical Sizing:** For mobile, headlines scale down to ensure they don't break across too many lines.
- **Hierarchy through Weight:** Use SemiBold (600) for headers and Regular (400) for long-form text. Bold (700) is reserved for the highest level of display importance.
- **Contrast:** Ensure all text on `#F5F5F7` maintains a contrast ratio of at least 4.5:1.

## Layout & Spacing

The layout philosophy follows a **Fluid Grid** model with generous margins to evoke a premium software feel.

- **Desktop:** 12-column grid with 40px outer margins and 20px gutters. Content is typically centered in a max-width container (1200px) for readability.
- **Mobile:** 4-column grid with 16px margins.
- **Rhythm:** All spacing must be multiples of 4px. Use `24px` (lg) for standard component grouping and `48px` (xxl) to separate major sections.
- **Safe Areas:** Respect system-level safe areas on mobile devices, especially when using fixed navigation bars.

## Elevation & Depth

Depth is conveyed through a combination of **Glassmorphism** and **Ambient Shadows**.

1.  **The Base:** Pure `#FFFFFF` canvas.
2.  **Translucent Overlays:** Navigation bars, toolbars, and context menus use a `backdrop-filter: blur(20px)` with a 70-80% opaque white background. This allows background colors to bleed through subtly, providing context.
3.  **Shadows:** Use highly diffused, multi-layered shadows.
    - *Low Elevation (Cards):* `0 2px 8px rgba(0,0,0,0.04)`
    - *High Elevation (Modals/Popovers):* `0 10px 40px rgba(0,0,0,0.12)`
4.  **Minimalist Borders:** Use a subtle 1px border (`#E5E5E7`) instead of shadows for flat elements like input fields or table rows to maintain a clean, "pro" look.

## Shapes

The design system uses a consistent **Rounded** language (Level 2).

- **Standard Elements:** 8px (0.5rem) for buttons, inputs, and small chips.
- **Large Elements:** 16px (1rem) for cards and main content containers.
- **Overlays:** 24px (1.5rem) for modal sheets and large popovers.

Avoid "pill-shaped" buttons for primary actions unless they are icons; stick to the 8px radius for a more structured, software-like appearance.

## Components

- **Buttons:** 
    - *Primary:* Solid `#007AFF` with white text. 
    - *Secondary:* `#F5F5F7` background with `#007AFF` text.
    - *State:* Use a subtle darken filter or 0.9 opacity on active/press states.
- **Cards:** White background, 1px border of `#E5E5E7`, and the "Low Elevation" shadow. Padding should be 24px (lg).
- **Input Fields:** 1px border of `#D1D1D6`, 8px corner radius. On focus, the border changes to Primary Blue with a 2px soft outer glow.
- **Chips:** Small (32px height), rounded 16px, light gray background (`#E5E5E7`) with `#1D1D1F` text.
- **Lists:** Use "In-set" style for mobile/sidebars—items have 8px padding and a subtle background fill on hover.
- **Glass Navigation:** Fixed top bars must use the frosted glass effect described in Elevation. Include a bottom border of 0.5px `#D1D1D6` to define the edge during scroll.
- **Progress Indicators:** Use the Success color (`#34C759`) for completed states to provide immediate visual reward.