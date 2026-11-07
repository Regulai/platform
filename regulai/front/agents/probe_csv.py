"""Fixed synthetic task 48 program. Executed ONLY inside a sandbox/template."""
import csv
import json
from pathlib import Path

with Path("/workspace/input/numbers.csv").open(newline="") as source:
    rows = list(csv.DictReader(source))
result = {"rows": len(rows), "total_cents": sum(int(row["amount_cents"]) for row in rows)}
Path("/workspace/output/totals.json").write_text(json.dumps(result))
print(json.dumps(result))
