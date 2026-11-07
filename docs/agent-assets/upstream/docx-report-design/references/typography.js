const { Paragraph, TextRun, ExternalHyperlink, HeadingLevel, PageBreak } = require("docx");
const { COLORS, FONT } = require("./brand-config");

/**
 * Heading level 1 — large bold, primary brand color.
 */
function heading1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 200 },
    children: [new TextRun({ text, bold: true, font: FONT, size: 32, color: COLORS.PRIMARY })]
  });
}

/**
 * Heading level 2 — medium bold, secondary brand color.
 */
function heading2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 280, after: 160 },
    children: [new TextRun({ text, bold: true, font: FONT, size: 26, color: COLORS.SECONDARY })]
  });
}

/**
 * Heading level 3 — small bold, primary brand color.
 */
function heading3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 200, after: 120 },
    children: [new TextRun({ text, bold: true, font: FONT, size: 22, color: COLORS.PRIMARY })]
  });
}

/**
 * Body text — 10pt regular.
 */
function bodyText(text) {
  return new Paragraph({
    spacing: { after: 120 },
    children: [new TextRun({ text, font: FONT, size: 20 })]
  });
}

/**
 * Metadata line — bold label + regular value on the same line.
 * e.g. metaLine("Report Date: ", "March 28, 2026")
 */
function metaLine(label, value) {
  return new Paragraph({
    spacing: { after: 60 },
    children: [
      new TextRun({ text: label, bold: true, font: FONT, size: 20 }),
      new TextRun({ text: value, font: FONT, size: 20 }),
    ]
  });
}

/**
 * Bullet point using proper numbering config.
 * Requires the Document to include the numbering config from page-setup.js.
 */
function bulletPoint(text) {
  return new Paragraph({
    spacing: { after: 80 },
    numbering: { reference: "doc-bullets", level: 0 },
    children: [new TextRun({ text, font: FONT, size: 20 })]
  });
}

/**
 * Empty spacer paragraph.
 */
function spacer() {
  return new Paragraph({ spacing: { after: 200 }, children: [] });
}

/**
 * Page break paragraph.
 */
function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

/**
 * External hyperlink — clickable link with display text.
 * e.g. externalLink("Click here", "https://example.com")
 * or with a label: externalLink("View spreadsheet", "https://...", "Source: ")
 */
function externalLink(text, url, label) {
  const children = [];
  if (label) {
    children.push(new TextRun({ text: label, bold: true, font: FONT, size: 20 }));
  }
  children.push(new ExternalHyperlink({
    link: url,
    children: [
      new TextRun({ text, style: "Hyperlink", font: FONT, size: 20 }),
    ],
  }));
  return new Paragraph({ spacing: { after: 60 }, children });
}

module.exports = {
  heading1,
  heading2,
  heading3,
  bodyText,
  metaLine,
  bulletPoint,
  spacer,
  pageBreak,
  externalLink,
};
