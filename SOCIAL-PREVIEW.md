# Social Preview Image Requirements

GitHub social preview images appear when the repository is shared on Twitter/X, Discord, Slack, LinkedIn, and other platforms that render Open Graph meta tags. A good social preview is the first impression most people get of the project.

---

## Image Specifications

| Property | Requirement |
|----------|-------------|
| **Dimensions** | 1280 x 640 px (2:1 aspect ratio) |
| **Format** | PNG or JPEG (PNG preferred for text clarity) |
| **File size** | Under 1 MB (GitHub compresses, but smaller is faster) |
| **Color space** | sRGB |
| **Safe zone** | Keep critical text/graphics within center 1100 x 560 px (edges may be cropped on some platforms) |

---

## Design Brief

### Theme
Dark security/infrastructure aesthetic. The project is a hardened container sandbox — the visual should convey **protection, isolation, and control** without looking like a generic cybersecurity stock image.

### Text Content

**Primary headline:**
```
OpenClaw-Vault
```

**Tagline (pick one or adapt):**
```
API keys never enter the container.
```
```
Defense-in-depth containment for OpenClaw.
```

**Feature callouts (optional, pick 2-3):**
- Proxy-side key injection
- Domain allowlist + exfiltration logging
- Read-only root, all caps dropped, custom seccomp
- Three-level kill switch

### Layout Suggestion

```
+----------------------------------------------------------+
|                                                          |
|              [Lock/Shield icon or glyph]                 |
|                                                          |
|                   OpenClaw-Vault                         |
|          API keys never enter the container.             |
|                                                          |
|   [ proxy-side injection ]  [ domain allowlist ]         |
|   [ read-only root ]        [ kill switch ]              |
|                                                          |
+----------------------------------------------------------+
```

---

## Color Palette

| Role | Color | Hex |
|------|-------|-----|
| **Background** | Dark charcoal / near-black | `#0d1117` or `#1a1b26` |
| **Primary text** | White / off-white | `#e6edf3` or `#c9d1d9` |
| **Accent** | Teal / security blue | `#58a6ff` or `#39d353` |
| **Secondary accent** | Muted orange (warnings) | `#d29922` |
| **Subtle elements** | Dark gray borders/dividers | `#30363d` |

The palette mirrors GitHub's dark theme and security dashboard conventions. Avoid bright reds (implies danger/broken) or neon greens (implies hacking).

---

## Typography

- **Headline:** Bold monospace or geometric sans-serif (JetBrains Mono, Inter, or similar)
- **Tagline:** Regular weight, same family, slightly smaller
- **Callouts:** Monospace at small size, styled as terminal badges or tags

---

## File Location

The social preview image has been generated and is ready for GitHub upload:
```
social-preview.png          # Final export (1280x640 PNG, ready to upload)
```

Upload it via **Settings > Social preview > Edit > Upload an image** on the GitHub repository page.
