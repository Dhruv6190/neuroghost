"""Directive scanner: finds text that tries to give the agent a standing order (H in the score)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class DirectiveResult:
    hit: bool
    categories: list[str] = field(default_factory=list)
    matches: list[str] = field(default_factory=list)


class DirectiveScanner:
    def __init__(self, rules: dict[str, list[str]]):
        self.rules: dict[str, list[re.Pattern[str]]] = {}
        for category, patterns in rules.items():
            self.rules[category] = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]

    def scan(self, scan_text: str) -> DirectiveResult:
        categories: list[str] = []
        matches: list[str] = []
        for category, patterns in self.rules.items():
            for pattern in patterns:
                m = pattern.search(scan_text)
                if m:
                    if category not in categories:
                        categories.append(category)
                    snippet = m.group(0).strip()
                    if len(snippet) > 80:
                        snippet = snippet[:77] + "..."
                    matches.append(snippet)
                    break  # one match per category is enough
        return DirectiveResult(hit=bool(categories), categories=categories, matches=matches)
