const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun,
  Header, Footer, AlignmentType, HeadingLevel,
  BorderStyle, LevelFormat, PageNumber
} = require("docx");
const { COLORS, FONT, ORG_NAME } = require("./brand-config");

/**
 * Returns the standard title block for a report.
 * @param {string} title - main title
 * @param {string} [subtitle] - optional subtitle line
 * @returns {Paragraph[]} array of Paragraphs to spread into children
 */
function titleBlock(title, subtitle) {
  const parts = [
    new Paragraph({
      spacing: { after: 100 },
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: title, bold: true, font: FONT, size: 44, color: COLORS.PRIMARY })]
    }),
  ];
  if (subtitle) {
    parts.push(new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 60 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: COLORS.PRIMARY, space: 8 } },
      children: [new TextRun({ text: subtitle, font: FONT, size: 24, color: COLORS.META_GRAY, italics: true })]
    }));
  }
  parts.push(new Paragraph({ spacing: { after: 200 }, children: [] }));
  return parts;
}

/**
 * Assemble a full Document with branding, styles, and page setup.
 *
 * @param {Array} children - array of Paragraphs and Tables
 * @param {object} [opts]
 * @param {string} [opts.headerText] - text in the page header (defaults to ORG_NAME from brand-config)
 */
function buildDocument(children, opts) {
  const { headerText = ORG_NAME } = opts || {};

  return new Document({
    styles: {
      default: {
        document: { run: { font: FONT, size: 20 } }
      },
      paragraphStyles: [
        {
          id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 32, bold: true, font: FONT, color: COLORS.PRIMARY },
          paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 },
        },
        {
          id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 26, bold: true, font: FONT, color: COLORS.SECONDARY },
          paragraph: { spacing: { before: 280, after: 160 }, outlineLevel: 1 },
        },
        {
          id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
          run: { size: 22, bold: true, font: FONT, color: COLORS.PRIMARY },
          paragraph: { spacing: { before: 200, after: 120 }, outlineLevel: 2 },
        },
      ],
    },
    numbering: {
      config: [
        {
          reference: "doc-bullets",
          levels: [{
            level: 0,
            format: LevelFormat.BULLET,
            text: "\u2022",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } },
          }],
        },
        {
          reference: "doc-numbers",
          levels: [{
            level: 0,
            format: LevelFormat.DECIMAL,
            text: "%1.",
            alignment: AlignmentType.LEFT,
            style: { paragraph: { indent: { left: 720, hanging: 360 } } },
          }],
        },
      ],
    },
    sections: [{
      properties: {
        page: {
          size: { width: 12240, height: 15840 },
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
        },
      },
      headers: {
        default: new Header({
          children: [new Paragraph({
            alignment: AlignmentType.RIGHT,
            border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: COLORS.PRIMARY, space: 4 } },
            children: [new TextRun({
              text: headerText,
              font: FONT, size: 16, color: COLORS.FOOTER_GRAY, italics: true,
            })]
          })]
        }),
      },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [
              new TextRun({ text: "Page ", font: FONT, size: 16, color: COLORS.FOOTER_GRAY }),
              new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 16, color: COLORS.FOOTER_GRAY }),
            ]
          })]
        }),
      },
      children,
    }],
  });
}

/**
 * Pack a Document to buffer and write to disk.
 * @param {Document} doc
 * @param {string} outputPath - absolute or relative path for the .docx file
 */
async function packAndWrite(doc, outputPath) {
  const buffer = await Packer.toBuffer(doc);
  fs.writeFileSync(outputPath, buffer);
  console.log("Created: " + outputPath);
}

module.exports = {
  titleBlock,
  buildDocument,
  packAndWrite,
};
