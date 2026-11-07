"""Offline design, editable-chart comparison and final-file render tests."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

sys.path.insert(0, '/lab/regulai/front/agents')
from presentation_program import build, edit, render, seal
from document_program import build as word, render as word_render, seal as word_seal

ROOT = Path('/evidence') / (sys.argv[1] if len(sys.argv) > 1 else 'design-v3')
ROOT.mkdir(exist_ok=False)
rows = [('Área Norte', 125), ('Piñón español', 250), ('Revisión técnica', 375)]
fields = {'title': 'Informe económico de España', 'section': 'Los importes corresponden a tres conceptos del archivo de origen. La tabla conserva el detalle y el gráfico permite comparar su distribución.', 'template': 'new'}
for name, template in [('new', 'new'), ('template', 'corporate'), ('long', 'new')]:
    folder = ROOT/name
    folder.mkdir()
    values = {**fields, 'template': template}
    if name == 'long':
        values['section'] = 'El análisis reúne los importes de las áreas de trabajo en España. Cada concepto mantiene su nombre original y su valor en euros. La revisión técnica debe contrastar el detalle con el archivo de origen antes de utilizar el total. Se conservan las tildes, la ñ y los símbolos monetarios: €, £ y $.'
    build(folder/'final.pptx', rows, values, Path('/lab/regulai/front/agents/runtime/templates/corporate.pptx'))
    render(folder)
    seal(folder)
    (folder/'fields.json').write_text(json.dumps(values))
folder = ROOT/'edit'
folder.mkdir()
edit(folder/'final.pptx', ROOT/'new/final.pptx', {'slide': 3, 'field': 'body', 'value': 'Revisión localizada: análisis de importes de España. Se conserva el resto de la presentación.'})
render(folder)
seal(folder)
for name, data in [('word', rows), ('word-long', [(f'Piñón español {n}', 125) for n in range(65)])]:
    folder = ROOT/name
    folder.mkdir()
    word_fields = {**fields, 'section': f'El informe recoge {len(data)} conceptos del archivo de origen. La tabla muestra los importes individuales y el total en euros para facilitar su revisión.'}
    word(Path('/lab/regulai/front/agents/runtime/templates/corporate.docx'), data, word_fields, folder/'final.docx')
    word_render(folder/'final.docx', folder)
    word_seal(folder)
print('Design corpus rendered from final DOCX/PPTX bytes')
