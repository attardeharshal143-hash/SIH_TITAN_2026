---
name: Cupertino Modern High-Impact
colors:
  surface: '#f9f9ff'
  surface-dim: '#d8d9e5'
  surface-bright: '#f9f9ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f1f3fe'
  surface-container: '#ecedf9'
  surface-container-high: '#e6e8f3'
  surface-container-highest: '#e0e2ed'
  on-surface: '#181c23'
  on-surface-variant: '#414755'
  inverse-surface: '#2d3039'
  inverse-on-surface: '#eef0fc'
  outline: '#717786'
  outline-variant: '#c1c6d7'
  surface-tint: '#005bc1'
  primary: '#0058bc'
  on-primary: '#ffffff'
  primary-container: '#0070eb'
  on-primary-container: '#fefcff'
  inverse-primary: '#adc6ff'
  secondary: '#4c4aca'
  on-secondary: '#ffffff'
  secondary-container: '#6664e4'
  on-secondary-container: '#fffbff'
  tertiary: '#9e3d00'
  on-tertiary: '#ffffff'
  tertiary-container: '#c64f00'
  on-tertiary-container: '#fffbff'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#d8e2ff'
  primary-fixed-dim: '#adc6ff'
  on-primary-fixed: '#001a41'
  on-primary-fixed-variant: '#004493'
  secondary-fixed: '#e2dfff'
  secondary-fixed-dim: '#c2c1ff'
  on-secondary-fixed: '#0c006a'
  on-secondary-fixed-variant: '#3631b4'
  tertiary-fixed: '#ffdbcc'
  tertiary-fixed-dim: '#ffb595'
  on-tertiary-fixed: '#351000'
  on-tertiary-fixed-variant: '#7c2e00'
  background: '#f9f9ff'
  on-background: '#181c23'
  surface-variant: '#e0e2ed'
  status-online: '#34C759'
  status-busy: '#FF9500'
  status-offline: '#8E8E93'
  diagram-line: '#D1D1D6'
  hero-scrim: rgba(0,0,0,0.4)
typography:
  display-hero:
    fontFamily: Geist
    fontSize: 80px
    fontWeight: '700'
    lineHeight: '1.05'
    letterSpacing: -0.04em
  display-hero-mobile:
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
  headline-serif:
    fontFamily: Source Serif 4
    fontSize: 28px
    fontWeight: '400'
    lineHeight: '1.4'
    letterSpacing: '0'
  body-lg:
    fontFamily: Geist
    fontSize: 18px
    fontWeight: '400'
    lineHeight: '1.6'
  body-md:
    fontFamily: Geist
    fontSize: 15px
    fontWeight: '400'
    lineHeight: '1.5'
  label-caps:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: 0.08em
  mono-label:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: '1.2'
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  hero-padding: 120px
  section-gap: 160px
  timeline-width: 2px
  node-gap: 64px
  diagram-gutter: 24px
---

## Brand & Style

This design system evolves the established "Cupertino" aesthetic into a high-impact, cinematic experience. It targets discerning professionals and luxury tech audiences who appreciate the intersection of engineering precision and editorial elegance. The emotional response is one of "Technical Sophistication"—feeling both incredibly powerful and effortlessly simple.

The design style is a refined mix of **Minimalism** and **High-Contrast Editorial**. It uses extreme whitespace and large-scale typography to create "Immersive Zen." While the core remains light and airy, it now incorporates dramatic cinematic layouts that utilize full-bleed imagery and structured vertical narratives to guide the user through complex information with ease.

## Colors

The palette is anchored in the classic "System Blue" but introduces specific semantic tokens for status and technical visualization.

- **Primary (#007AFF):** The signature interactive color. Used for progress indicators, primary calls-to-action, and active timeline nodes.
- **Secondary (#5856D6):** A deep indigo used for accenting architectural diagrams or secondary features to provide depth without breaking the professional tone.
- **System Status:** Professional indicators use calibrated system greens, oranges, and grays to indicate "Ready," "Deploying," or "Offline" states.
- **Surface Layering:** The primary background is white (`#FFFFFF`), while secondary containers use `#F5F5F7`. For diagrams, a tertiary layer of `#E5E5E7` provides subtle contrast for node boxes.

## Typography

The system utilizes a sophisticated **Sans/Serif mix**. While **Geist** handles the technical and display heavy-lifting, **Source Serif 4** is introduced for editorial sub-headings and pull-quotes to add a layer of prestige and legibility.

- **Immersive Heroes:** Use `display-hero` with tight tracking for maximum impact. Headlines should be centered within full-bleed sections.
- **Technical Content:** Architectural labels and status indicators use **JetBrains Mono** for a "developer-ready" aesthetic.
- **Editorial Contrast:** Use the Serif face for narrative descriptions that sit between high-impact headlines and technical body copy.

## Layout & Spacing

The layout moves beyond simple grids into a **Cinematic Vertical Flow**.

- **Hero Sections:** Full-bleed (100vh) height with content vertically and horizontally centered. Use a minimum of 120px internal padding to ensure content never feels crowded.
- **Vertical Timelines:** A central or left-aligned 2px vertical spine (`#D1D1D6`) connects progress indicators. Nodes are spaced exactly 64px apart to maintain a rhythmic "scrolling story."
- **Architecture Diagrams:** Use a specialized sub-grid where boxes are linked by 1.5px lines. Maintain a 24px gutter between nodes for clarity.
- **Breakpoints:** On mobile, the vertical timeline spine shifts to the far left (16px from edge) to maximize space for content cards.

## Elevation & Depth

Hierarchy is achieved through "Soft Volume" rather than harsh shadows.

- **Minimalist Cards:** These do not use borders. Instead, they utilize a very large, soft shadow (`0 20px 50px rgba(0,0,0,0.04)`) against the `#F5F5F7` background to appear as if they are floating slightly above the surface.
- **Glassmorphism:** Reserved for the global navigation and timeline "sticky" headers. Use a `backdrop-filter: blur(30px)` to create a premium frosted effect that picks up the colors of the hero imagery beneath.
- **Diagram Depth:** Architecture boxes use a subtle 1px inset stroke to look "etched" into the page, rather than sitting on top of it.

## Shapes

The shape language remains "Rounded" (Level 2) to maintain the friendly but professional software feel.

- **Status Indicators:** Perfect circles (999px) for online/offline pips.
- **Cards & Diagram Nodes:** 16px (1rem) for a modern, approachable container style.
- **Connecting Lines:** 1.5px thickness with "Round" line caps and joins to match the corner radii of the boxes they connect.

## Components

- **Immersive Hero:** A container with `min-height: 100vh`, utilizing a background image or subtle gradient. Typography must be centered with a max-width of 800px.
- **Vertical Timeline:** 
    - *The Spine:* A 2px vertical line.
    - *The Node:* A 12px circle. If "Active," it has a 4px Primary Blue border and white center. If "Completed," it is solid Primary Blue with a checkmark.
- **System Status Pips:** 8px circles with a soft "glow" (shadow) of the same color (e.g., green glow for online) to indicate active power/state.
- **Minimalist Cards:** Pure white, no border, 16px radius, 48px internal padding. This "generous whitespace" is mandatory for the premium aesthetic.
- **Architecture Nodes:** 
    - *Box:* 1px border (`#D1D1D6`), light gray fill (`#F5F5F7`), JetBrains Mono text.
    - *Connectors:* 1.5px lines with arrowheads pointing to the flow of data.
- **Progress Indicators:** Linear bars should be 4px tall with fully rounded end-caps. The track should be `#E5E5E7` and the indicator Primary Blue.