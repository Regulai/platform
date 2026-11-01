"""Arrange existing local renders for inspection; no generated document editing."""
import json
from pathlib import Path
import sys
from PIL import Image, ImageDraw

root=Path(sys.argv[1])
for case in root.iterdir():
    if not case.is_dir(): continue
    pages=sorted(case.glob('page-*.png'))
    if not pages: continue
    opened=[Image.open(p).convert('RGB') for p in pages]
    width=max(p.width for p in opened); height=max(p.height for p in opened)+32
    sheet=Image.new('RGB',(width*2,height*((len(opened)+1)//2)), '#dce4e4')
    for index,page in enumerate(opened):
        left=(index%2)*width; top=(index//2)*height
        ImageDraw.Draw(sheet).text((left+8,top+8),case.name+' / '+pages[index].name,fill='black')
        sheet.paste(page,(left,top+32))
    sheet.save(case/'gallery.png')
    for page in opened: page.close()
