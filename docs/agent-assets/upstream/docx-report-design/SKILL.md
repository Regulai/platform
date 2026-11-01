---
name: docx-report
description: >-
  Generate polished .docx reports with custom branding. Use when the user asks
  to create a report, analysis document, data summary, or formatted deliverable
  as a .docx file. This skill provides shared helpers for consistent branded
  tables, typography, and page layout.
---

# .docx Report Skill

Generate professional Word documents with custom branding using the `docx` npm package and shared helper modules.

## Setup

On first use, install the dependency:

```bash
cd <skill-path>/references && npm install
```

Check: if `references/node_modules/docx` does not exist, run the install before proceeding.

### Brand Customization

Edit `references/brand-config.js` to set your organization name, font, and color palette. This is the **only file** you need to change to match your brand. See `references/color-palette.md` for guidance on choosing colors.

## Workflow

### Step 1: Understand the Content

Before writing any code, determine:
- What data or analysis needs to be presented?
- What sections does the report need? (title, summary tables, breakdowns, observations, methodology, etc.)
- What table schemas are needed? (column names, widths, alignment)

### Step 2: Plan Document Structure

Sketch the section order:
1. **Title block** — `titleBlock(title, subtitle)` + `metaLine()` for date/source metadata
2. **Data sections** — `heading1()` + `createTable()` for each major table, separated by `pageBreak()`
3. **Narrative sections** — `heading1()` + `heading2()` + `bodyText()` + `bulletPoint()`
4. **Methodology** — at the end, as bullet points

### Step 3: Generate the Report Script

If the user doesn't specify an output location, default to the `reports/` directory. Create it if it doesn't exist (`mkdir -p reports`), then create a JS file (e.g., `reports/my_report.js`) that:

```javascript
const path = require("path");

// Import shared helpers — always use absolute path to skill references
const SKILL_REF = "<skill-path>/references";
const { createTable, PAGE_W } = require(path.join(SKILL_REF, "table-templates"));
const { heading1, heading2, bodyText, bulletPoint, metaLine, spacer, pageBreak } = require(path.join(SKILL_REF, "typography"));
const { titleBlock, buildDocument, packAndWrite } = require(path.join(SKILL_REF, "page-setup"));

const children = [];
children.push(...titleBlock("Report Title", "Subtitle"));
children.push(metaLine("Report Date: ", "March 28, 2026"));
// ... add sections, tables, observations ...

const doc = buildDocument(children, { headerText: "My Org — Report Title" });
packAndWrite(doc, "reports/my_report.docx");
```

Replace `<skill-path>` with the actual path to this skill directory (e.g., `/path/to/project/.claude/skills/docx-report-skill`).

### Step 4: Run & Validate

```bash
node reports/my_report.js
```

### Step 5: Present & Iterate

**After every run** (first creation and every subsequent edit), tell the user:

> "Here's your report. Take a look — if you want any changes, let me know. Once you're happy with it, I'll clean up the build script."

Always ask this after each iteration — not just the first time. If the user requests changes, modify the existing JS file and rerun it. Do **not** recreate the script from scratch — editing is faster and preserves context.

### Step 6: Clean Up

Once the user is satisfied with the report, delete the JS build script:

```javascript
fs.unlinkSync("reports/my_report.js");
```

The `.docx` file is the deliverable. The build script is a temporary artifact.

## Helper API Reference

### table-templates.js

| Export | Description |
|--------|-------------|
| `COLORS` | Object with all brand color hex constants (from `brand-config.js`) |
| `FONT` | Font family string (from `brand-config.js`) |
| `PAGE_W` | `9360` — US Letter content width in DXA at 1" margins |
| `borders` | Standard border config object |
| `cellMargins` | Standard cell margin config `{ top: 60, bottom: 60, left: 100, right: 100 }` |
| `headerCell(text, width)` | Branded header cell with white bold centered text |
| `dataCell(text, width, opts?)` | Data cell. opts: `{ isAlt, align, bold }` |
| `createTable(headers, rows, columnWidths, opts?)` | Full table with branded headers + alternating rows. opts: `{ aligns: ["left","center","right"], boldCols: [false,true] }` |
| `AlignmentType` | Re-exported from docx |
| `WidthType` | Re-exported from docx |
| `BorderStyle` | Re-exported from docx |
| `ShadingType` | Re-exported from docx |

### typography.js

| Export | Description |
|--------|-------------|
| `heading1(text)` | Large bold, primary brand color, HEADING_1 |
| `heading2(text)` | Medium bold, secondary brand color, HEADING_2 |
| `heading3(text)` | Small bold, primary brand color, HEADING_3 |
| `bodyText(text)` | 10pt regular body paragraph |
| `metaLine(label, value)` | Bold label + regular value on same line |
| `bulletPoint(text)` | Bullet using proper numbering config |
| `spacer()` | Empty paragraph with spacing |
| `pageBreak()` | Page break paragraph |
| `externalLink(text, url, label?)` | Clickable hyperlink. Optional bold label prefix. |

### page-setup.js

| Export | Description |
|--------|-------------|
| `titleBlock(title, subtitle?)` | Returns `Paragraph[]` — centered title + subtitle with brand-colored border |
| `buildDocument(children, opts?)` | Full Document with styles, numbering, header, footer, page setup. opts: `{ headerText }` (defaults to ORG_NAME from brand-config) |
| `packAndWrite(doc, outputPath)` | Pack to buffer and write .docx file |

## Common Pitfalls

### Do NOT import directly from `docx`

**Never** do this in your report script:

```javascript
// WRONG — causes "rootKey" validation errors
const { Paragraph, TextRun, ExternalHyperlink } = require("docx");
// or
const { Paragraph, TextRun } = require(path.join(SKILL_REF, "node_modules/docx"));
```

The `docx` library uses `instanceof` checks internally. When your script imports from a different `require()` path than the helpers, Node.js creates **separate module instances**. Objects from your import fail the helpers' `instanceof` checks, causing the XML serializer to emit invalid `rootKey` elements instead of proper `<w:p>` nodes — resulting in:

```
Element 'rootKey': This element is not expected. Expected is ( {http://schemas.openxmlformats.org/wordprocessingml/2006/main}sectPr ).
```

**Instead**, use only the helper functions (`bodyText`, `metaLine`, `bulletPoint`, `heading1`, etc.) for all content. If you need raw docx classes (e.g., `AlignmentType`, `BorderStyle`), import them from `table-templates.js` which re-exports them from the correct module instance:

```javascript
// CORRECT — use re-exports from helpers
const { AlignmentType, BorderStyle, COLORS } = require(path.join(SKILL_REF, "table-templates"));
```

### Hyperlinks

Use the `externalLink()` helper from `typography.js` for clickable links:

```javascript
// Clickable hyperlink with optional bold label
children.push(externalLink("View Spreadsheet", "https://docs.google.com/spreadsheets/d/ABC123", "Source: "));
```

**Never** construct `ExternalHyperlink` directly — always use the `externalLink()` helper.

## Design Principles

1. **Always use `buildDocument()`** to create the Document — never construct `new Document()` directly. It includes required numbering configs, styles, header, and footer.

2. **Column widths must sum to `PAGE_W`** (9360 DXA). Pre-calculated suggestions:

   | Layout | Column Widths |
   |--------|--------------|
   | 2 equal | `[4680, 4680]` |
   | 3 equal | `[3120, 3120, 3120]` |
   | 4-col (rank, code, desc, count) | `[700, 1200, 5460, 2000]` |
   | 4-col (code, desc, all, active) | `[1100, 4460, 1900, 1900]` |
   | 3-col (category, all, active) | `[4360, 2500, 2500]` |
   | 7-col (label + 6 values) | `[2460, 1150, 1150, 1150, 1150, 1150, 1150]` |

3. **Use `ShadingType.CLEAR`** for fills — never `SOLID` (causes black backgrounds).

4. **Page breaks** between major sections to prevent table splits.

5. **All fonts come from `brand-config.js`** — the helpers enforce this.

6. **Colors only from the palette** — see `references/color-palette.md`.

## Quality Checklist

- [ ] Script runs without errors (`node reports/my_report.js`)
- [ ] All tables have branded header rows
- [ ] Column widths sum to 9360
- [ ] Page breaks separate major sections
- [ ] Title block present with bottom border
- [ ] Header and footer appear on every page
- [ ] No direct `new Document()` usage — uses `buildDocument()`
- [ ] No direct `require("docx")` or `require(".../node_modules/docx")` — use only helper functions and re-exports
- [ ] Build script deleted after user approves the final report

## Example

See `references/generate-example.js` for a complete, runnable example.
