"""Reviewed Python program installed read-only in the spreadsheet microVM.

Only values-only synthetic inputs are admitted by the application. No user code,
macros, links, provider clients or runtime dependency installation are supported.
"""
import argparse
import io
import json
from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET

import pandas as pd
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill


def build(source, output, title):
    if source.suffix == '.csv':
        frame = pd.read_csv(source, dtype={'item': str, 'amount_cents': 'int64'}, keep_default_na=False)
    else:
        frame = pd.read_excel(source, dtype={'item': str, 'amount_cents': 'int64'}, keep_default_na=False)
    total = int(frame['amount_cents'].sum())
    book = Workbook()
    sheet = book.active
    sheet.title = 'Resumen'
    sheet['A1'] = title
    sheet['A1'].data_type = 's'
    sheet['A1'].font = Font(name='Liberation Sans', size=18, bold=True, color='172D4D')
    sheet.merge_cells('A1:C1')
    for column, heading in enumerate(['Concepto', 'Importe (céntimos)', 'Importe (€)'], 1):
        cell = sheet.cell(3, column, heading)
        cell.font = Font(name='Liberation Sans', color='FFFFFF', bold=True)
        cell.fill = PatternFill('solid', fgColor='172D4D')
    for n, row in enumerate(frame.itertuples(index=False), 4):
        sheet.cell(n, 1, str(row.item)).data_type = 's'
        sheet.cell(n, 2, int(row.amount_cents))
        sheet.cell(n, 3, f'=B{n}/100').number_format = '#,##0.00 "€"'
    end = len(frame) + 4
    sheet.cell(end, 1, 'Total')
    sheet.cell(end, 2, f'=SUM(B4:B{end-1})')
    sheet.cell(end, 3, f'=B{end}/100').number_format = '#,##0.00 "€"'
    for cell in sheet[end]:
        cell.font = Font(bold=True, color='172D4D')
        cell.fill = PatternFill('solid', fgColor='E7EDF5')
    sheet.column_dimensions['A'].width = 42
    sheet.column_dimensions['B'].width = 24
    sheet.column_dimensions['C'].width = 22
    sheet.freeze_panes = 'A4'
    sheet.auto_filter.ref = f'A3:C{end-1}'
    sheet.print_options.horizontalCentered = True
    sheet.print_area = f'A1:C{end}'
    sheet.sheet_properties.pageSetUpPr.fitToPage = True
    sheet.page_setup.orientation = 'landscape'
    sheet.page_setup.paperSize = sheet.PAPERSIZE_A4
    sheet.page_setup.fitToWidth = 1
    book.save(output)
    book.close()
    # Raw diagnostic is retained privately by the result gate, not model data.
    print(json.dumps({'rows': len(frame), 'pandas_total_cents': total}))


def rename(source, output, title):
    # A title-only edit must not invalidate formula caches or reserialize styles.
    # Change only the XML for A1; all other ZIP parts remain byte-identical.
    ns = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
    with zipfile.ZipFile(source) as old, zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as new:
        for item in old.infolist():
            data = old.read(item)
            if item.filename == 'xl/worksheets/sheet1.xml':
                root = ET.fromstring(data)
                cell = root.find(f'.//{ns}c[@r="A1"]')
                if cell is None:
                    raise ValueError('Missing title')
                cell.set('t', 'inlineStr')
                for child in list(cell):
                    cell.remove(child)
                inline = ET.SubElement(cell, ns + 'is')
                ET.SubElement(inline, ns + 't').text = title
                data = ET.tostring(root, encoding='utf-8', xml_declaration=True)
            new.writestr(item, data)


def check(path):
    formulas, cached = load_workbook(path), load_workbook(path, data_only=True)
    sheet, values = formulas.active, cached.active
    end = sheet.max_row
    total = sum(int(sheet.cell(n, 2).value) for n in range(4, end))
    if sheet.cell(end, 2).data_type != 'f' or values.cell(end, 2).value != total:
        raise ValueError('Recalculation failed')
    for n in range(4, end + 1):
        amount = sheet.cell(n, 2).value if n < end else total
        if sheet.cell(n, 3).data_type != 'f' or values.cell(n, 3).value != amount / 100:
            raise ValueError('Formula result failed')
    formulas.close()
    cached.close()
    print('Workbook reopened and checked')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['build', 'rename', 'check'])
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--fields', type=Path)
    args = parser.parse_args()
    if args.operation == 'check':
        check(args.source)
    else:
        title = json.loads(args.fields.read_text())['title']
        (build if args.operation == 'build' else rename)(args.source, args.output, title)


if __name__ == '__main__':
    main()
