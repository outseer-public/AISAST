"""JSON output reporter"""

import json
from pathlib import Path
from typing import Union
from aisast.models.result import ScanResult


class JSONReporter:
    """Saves scan results to JSON files"""

    @staticmethod
    def save(result: ScanResult, output_path: Union[str, Path]) -> None:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)

    @staticmethod
    def load(input_path: Union[str, Path]) -> dict:
        with open(input_path, "r", encoding="utf-8") as f:
            return json.load(f)
