import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Workbook, SpreadsheetFile } from '@oai/artifact-tool';

const root = path.dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(await fs.readFile(path.join(root, 'fixtures', 'inventory-source.json'), 'utf8'));
const workbook = Workbook.create();
for (const [name, rows] of Object.entries(data)) {
  const sheet = workbook.worksheets.add(name);
  const range = sheet.getRangeByIndexes(0, 0, rows.length, rows[0].length);
  range.values = rows;
  range.format.font = {name: 'Arial', size: 11};
  range.format.rowHeight = 22;
  range.format.columnWidth = 22;
  sheet.getRangeByIndexes(0, 0, 1, rows[0].length).format = {
    fill: '#17324D', font: {name: 'Arial', size: 11, bold: true, color: '#FFFFFF'},
  };
  sheet.showGridLines = false;
}
workbook.recalculate();
console.log((await workbook.inspect({kind: 'sheet', include: 'id,name'})).ndjson);
for (const name of Object.keys(data)) {
  const preview = await workbook.render({sheetName: name, autoCrop: 'all', scale: 1, format: 'png'});
  await fs.writeFile(path.join(root, 'verification', `${name}.png`), new Uint8Array(await preview.arrayBuffer()));
}
const output = await SpreadsheetFile.exportXlsx(workbook);
await output.save(path.join(root, 'fixtures', 'inventory.xlsx'));
