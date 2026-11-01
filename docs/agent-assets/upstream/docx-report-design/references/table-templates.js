const {
  Table, TableRow, TableCell, Paragraph, TextRun,
  AlignmentType, BorderStyle, WidthType, ShadingType
} = require("docx");

const { COLORS, FONT } = require("./brand-config");

// US Letter (12240 DXA) minus 1-inch margins (2 × 1440) = 9360
const PAGE_W = 9360;

const border = { style: BorderStyle.SINGLE, size: 1, color: COLORS.LIGHT_BORDER };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };

/**
 * Create a branded header cell with white bold text on primary-color background.
 */
function headerCell(text, width) {
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: COLORS.HEADER_BG, type: ShadingType.CLEAR },
    margins: cellMargins,
    verticalAlign: "center",
    children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text, bold: true, color: COLORS.HEADER_TEXT, font: FONT, size: 18 })]
    })]
  });
}

/**
 * Create a data cell with optional alternating shading, alignment, and bold.
 * @param {string} text
 * @param {number} width - DXA width
 * @param {object} [opts]
 * @param {boolean} [opts.isAlt=false] - alternating row shading
 * @param {string}  [opts.align=AlignmentType.LEFT]
 * @param {boolean} [opts.bold=false]
 */
function dataCell(text, width, opts) {
  const { isAlt = false, align = AlignmentType.LEFT, bold = false } = opts || {};
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: isAlt ? { fill: COLORS.ALT_ROW, type: ShadingType.CLEAR } : undefined,
    margins: cellMargins,
    children: [new Paragraph({
      alignment: align,
      children: [new TextRun({ text: String(text), font: FONT, size: 18, bold })]
    })]
  });
}

/**
 * Build a full table with branded headers and alternating row shading.
 *
 * @param {string[]} headers - header labels
 * @param {Array<Array<string|number>>} rows - data rows
 * @param {number[]} columnWidths - DXA widths (must sum to PAGE_W = 9360)
 * @param {object} [opts]
 * @param {Array<string>} [opts.aligns] - per-column alignment ("left","center","right")
 * @param {Array<boolean>} [opts.boldCols] - per-column bold flag
 */
function createTable(headers, rows, columnWidths, opts) {
  const { aligns, boldCols } = opts || {};

  const alignMap = { left: AlignmentType.LEFT, center: AlignmentType.CENTER, right: AlignmentType.RIGHT };

  const headerRow = new TableRow({
    children: headers.map((h, i) => headerCell(h, columnWidths[i]))
  });

  const dataRows = rows.map((row, ri) => new TableRow({
    children: row.map((val, ci) => dataCell(val, columnWidths[ci], {
      isAlt: ri % 2 === 1,
      align: aligns ? (alignMap[aligns[ci]] || AlignmentType.LEFT) : AlignmentType.LEFT,
      bold: boldCols ? boldCols[ci] : false,
    }))
  }));

  return new Table({
    width: { size: PAGE_W, type: WidthType.DXA },
    columnWidths,
    rows: [headerRow, ...dataRows],
  });
}

module.exports = {
  COLORS,
  FONT,
  PAGE_W,
  borders,
  cellMargins,
  headerCell,
  dataCell,
  createTable,
  // Re-export commonly needed docx classes
  AlignmentType,
  WidthType,
  BorderStyle,
  ShadingType,
};
