"""Build the single task-50 spreadsheet template on the prepared E2B host."""
import json
from pathlib import Path
from e2b import Template
from front.agents.sandbox_pool import e2b_options

def build(config):
    root = Path('/app')
    # All dependencies/files are preinstalled in OCI. No per-command snapshots:
    # the small 48 host retains their mappings during a build and exhausts RAM.
    template = Template(file_context_path=root).from_image(config['image'])
    result = Template.build(template, alias=config['template'], cpu_count=1, memory_mb=1024,
        on_build_logs=lambda entry: print(entry.message, flush=True), **e2b_options(config))
    print('Built spreadsheet template: ' + result.template_id, flush=True)
    return result


if __name__ == '__main__':
    import sys
    build(json.loads(Path(sys.argv[1]).read_text()))
