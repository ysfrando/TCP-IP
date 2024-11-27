from dataclasses import dataclass
from typing import List

@dataclass
class BBTarget:
    url: str
    name: str
    environment: str
    severity_threshold: str
    excluded_templates: List[str]
