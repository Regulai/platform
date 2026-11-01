# docx-report-skill

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) skill for generating professional, branded `.docx` reports using Node.js.

Give Claude a prompt like **"create a report summarizing this data using the docx report skill"** and it will generate a polished Word document with your organization's branding — tables, headings, page numbers, and all.

![Example report output](references/example-output.png)

## Features

- **Branded tables** with colored headers and alternating row shading
- **Typography hierarchy** — three heading levels, body text, bullet points, metadata lines
- **Page layout** — title blocks, headers, footers with automatic page numbers
- **Hyperlinks** — clickable external links with optional labels
- **Single-file customization** — edit one config file to match your brand

## Installation

Clone this repo into your project's `.claude/skills/` directory:

```bash
cd your-project
mkdir -p .claude/skills
git clone https://github.com/drharunyuksel/docx-report-skill.git .claude/skills/docx-report-skill
```

Then install the Node.js dependency:

```bash
cd .claude/skills/docx-report-skill/references && npm install
```

That's it. Claude Code will automatically detect the skill from `SKILL.md`.

## Customization

Edit **one file** to match your brand: `references/brand-config.js`

```javascript
module.exports = {
  ORG_NAME: "Your Company",       // Used in page headers
  FONT: "Arial",                  // Font for all text
  COLORS: {
    PRIMARY: "0D7377",            // Headings, table headers, borders
    SECONDARY: "1A1A2E",          // Heading 2 text
    HEADER_BG: "0D7377",          // Table header background
    HEADER_TEXT: "FFFFFF",        // Table header text (white)
    ALT_ROW: "EDF7F7",           // Alternating row shading
    LIGHT_BORDER: "CCCCCC",      // Table borders
    SECTION_BG: "F0F9F9",        // Callout backgrounds
    META_GRAY: "666666",         // Subtitle text
    FOOTER_GRAY: "999999",       // Header/footer text
  },
};
```

See `references/color-palette.md` for tips on choosing colors.

## Usage

Ask Claude to create a report:

```
Create a .docx report summarizing the Q1 sales data using the docx report skill
```

Claude will generate a Node.js script using the shared helpers, run it, and produce a `.docx` file.

### Manual usage

You can also run the example directly:

```bash
cd .claude/skills/docx-report-skill/references
node generate-example.js
# Creates: example-output.docx
```

## How It Works

The skill provides three helper modules that report scripts import:

| Module | Purpose |
|--------|---------|
| `table-templates.js` | Table builder with branded headers and alternating rows |
| `typography.js` | Heading hierarchy, body text, bullets, links |
| `page-setup.js` | Document structure, title blocks, headers/footers, page layout |

All modules read from `brand-config.js` — no hardcoded colors or fonts anywhere.

> **Important:** Report scripts must never `require("docx")` directly. The helpers re-export everything you need. See "Common Pitfalls" in `SKILL.md` for details.

## Requirements

- Node.js 18+
- Claude Code (or any AI agent that supports skills)

## License

MIT
