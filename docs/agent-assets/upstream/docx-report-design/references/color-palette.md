# Brand Color Palette for .docx Reports

All hex values are 6-digit without `#` prefix (docx-js convention).

## Customization

Edit `brand-config.js` to change these values. The table below documents the default palette and how each color is used.

## Default Color Constants

| Key in brand-config.js | Default Hex | Usage |
|------------------------|-------------|-------|
| `PRIMARY` | `0D7377` | Heading 1/3 text, table header background, title text, decorative borders |
| `SECONDARY` | `1A1A2E` | Heading 2 text color |
| `HEADER_BG` | `0D7377` | Table header cell fill (often same as PRIMARY) |
| `HEADER_TEXT` | `FFFFFF` | White text on header cells |
| `ALT_ROW` | `EDF7F7` | Alternating table row shading (light tint of primary) |
| `LIGHT_BORDER` | `CCCCCC` | Table cell borders |
| `SECTION_BG` | `F0F9F9` | Optional callout/section background |
| `META_GRAY` | `666666` | Subtitle and metadata text |
| `FOOTER_GRAY` | `999999` | Page header and footer text |

## Usage Rules

- **Table headers**: Always `HEADER_BG` fill + `HEADER_TEXT` text
- **Alternating rows**: Even rows = no fill, odd rows = `ALT_ROW`
- **Borders**: Always `LIGHT_BORDER` with `BorderStyle.SINGLE`, size 1
- **Typography hierarchy**: H1 = `PRIMARY`, H2 = `SECONDARY`, H3 = `PRIMARY`
- **Decorative borders** (title underline, header rule): Use `PRIMARY`

## Tips for Choosing Your Own Colors

1. **PRIMARY** should be your strongest brand color — it's used the most
2. **SECONDARY** should contrast well with PRIMARY — it's used for H2 headings
3. **ALT_ROW** should be a very light tint of your PRIMARY (5-10% opacity equivalent)
4. **HEADER_BG** is usually the same as PRIMARY, but can differ for table-heavy reports
5. **Keep META_GRAY and FOOTER_GRAY as neutral grays** — they provide visual rest
