/**
 * Brand configuration for .docx report generation.
 *
 * ★ This is the ONLY file you need to edit to match your organization's brand.
 *
 * Colors are 6-digit hex WITHOUT the "#" prefix (docx-js convention).
 * Font must be a font name available on the system generating the .docx.
 */
module.exports = {
  /** Organization name — used in default page headers */
  ORG_NAME: "Acme Corp",

  /** Font family for all text in the document */
  FONT: "Arial",

  /** Brand color palette */
  COLORS: {
    /** Primary brand color — headings (H1, H3), table headers, title, decorative borders */
    PRIMARY: "0D7377",

    /** Secondary brand color — Heading 2 text */
    SECONDARY: "1A1A2E",

    /** Table header cell background (often same as PRIMARY) */
    HEADER_BG: "0D7377",

    /** Table header cell text color */
    HEADER_TEXT: "FFFFFF",

    /** Alternating table row shading (light tint of primary) */
    ALT_ROW: "EDF7F7",

    /** Table cell border color */
    LIGHT_BORDER: "CCCCCC",

    /** Optional callout/section background */
    SECTION_BG: "F0F9F9",

    /** Subtitle and metadata text color */
    META_GRAY: "666666",

    /** Page header and footer text color */
    FOOTER_GRAY: "999999",
  },
};
