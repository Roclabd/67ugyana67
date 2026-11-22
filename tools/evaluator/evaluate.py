#!/usr/bin/env python3
"""Сверяет JSON-отчёт анализаторов с эталоном авторов набора."""

import argparse
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, replace
import json
from pathlib import Path
import sys
from typing import Callable, NamedTuple, TypeVar


TRAINING = Path(__file__).resolve().parents[2] / "fixtures" / "training"
DEFAULT_TRUTH = TRAINING / "ground-truth" / "training-findings.json"
CATEGORIES = ("SECRET", "SAST", "SCA")
SCA_CLASS = "known-vulnerable-dependency"
Row = TypeVar("Row")


class InputError(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    category: str
    path: str
    kind: str
    lines: tuple[int, int] | None = None
    dependency: tuple[str, str, str] | None = None
    advisories: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, ...]:
        if self.dependency is not None:
            return (self.category, self.path, *self.dependency)
        return (self.category, self.path, self.kind)


class Reference(NamedTuple):
    id: str
    finding: Finding


class Metrics(NamedTuple):
    tp: int
    fp: int
    fn: int

    def row(self) -> list[str]:
        precision = f"{self.tp / (self.tp + self.fp):.2%}" if self.tp + self.fp else "—"
        recall = f"{self.tp / (self.tp + self.fn):.2%}" if self.tp + self.fn else "—"
        return [str(self.tp), str(self.fp), str(self.fn), precision, recall]


def load_object(path: Path) -> dict:
    with path.open(encoding="utf-8-sig") as source:
        try:
            data = json.load(source)
        except json.JSONDecodeError as error:
            raise InputError(
                f"{path}: ошибка JSON, строка {error.lineno}, столбец {error.colno}"
            ) from error
        except UnicodeDecodeError as error:
            raise InputError(f"{path}: требуется кодировка UTF-8") from error
    if not isinstance(data, dict):
        raise InputError(f"{path}: в корне требуется объект")
    return data


def require_text(row: dict, key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{key}: требуется непустая строка")
    return value


def parse_finding(row: dict, reference: bool) -> Finding:
    category = require_text(row, "category")
    if category not in CATEGORIES:
        raise InputError("category: требуется SECRET, SAST или SCA")
    path = require_text(row, "path").replace("\\", "/")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise InputError("path: управляющие символы недопустимы")
    components = path.split("/")
    if path.startswith("/") or ":" in path or ".." in components:
        raise InputError("path: требуется относительный путь без компонента '..'")
    path = "/".join(part for part in components if part and part != ".")
    if not path:
        raise InputError("path: требуется путь к файлу")

    if category == "SCA":
        dependency = (
            require_text(row, "group"), require_text(row, "artifact"), require_text(row, "version")
        )
        if reference:
            ids = row.get("advisoryIds")
            if not isinstance(ids, list) or not ids or any(
                not isinstance(item, str) or not item.strip() for item in ids
            ):
                raise InputError("advisoryIds: требуется непустой массив непустых строк")
            advisories = tuple(ids)
        else:
            advisories = (require_text(row, "advisoryId"),)
        return Finding(category, path, SCA_CLASS, dependency=dependency, advisories=advisories)

    kind = require_text(row, "class")
    start = row.get("line")
    end = row.get("endLine", start)
    if type(start) is not int or start < 1:
        raise InputError("line: требуется целое число от 1")
    if type(end) is not int or end < start:
        raise InputError("endLine: требуется целое число не меньше line")
    if not reference and end - start > 14:
        raise InputError("endLine: допустимый диапазон содержит от 1 до 15 строк")
    return Finding(category, path, kind, lines=(start, end))


def parse_reference(row: dict) -> Reference:
    return Reference(require_text(row, "id"), parse_finding(row, reference=True))


def load_rows(path: Path, data: dict, key: str, parser: Callable[[dict], Row]) -> list[Row]:
    rows = data.get(key, [] if key == "controls" else None)
    if not isinstance(rows, list):
        raise InputError(f"{path}: {key} должен быть массивом")
    parsed = []
    for index, row in enumerate(rows):
        try:
            if not isinstance(row, dict):
                raise InputError("требуется объект")
            parsed.append(parser(row))
        except InputError as error:
            raise InputError(f"{path}: {key}[{index}]: {error}") from error
    return parsed


def overlap(first: tuple[int, int], second: tuple[int, int]) -> bool:
    return first[0] <= second[1] and second[0] <= first[1]


def match(first: Finding, expected: Finding) -> bool:
    if first.key != expected.key:
        return False
    if first.lines is not None and expected.lines is not None:
        return overlap(first.lines, expected.lines)
    return first.advisories[0] in expected.advisories


def maximum_matching(findings: list[Finding], truth: list[Reference]) -> dict[int, int]:
    """Return report-index to truth-index pairs using augmenting paths."""
    by_key = defaultdict(list)
    for index, expected in enumerate(truth):
        by_key[expected.finding.key].append(index)
    candidates = [
        [index for index in by_key[finding.key] if match(finding, truth[index].finding)]
        for finding in findings
    ]

    matched = {}
    owners = {}
    for start in range(len(findings)):
        queue = deque([start])
        visited = {start}
        parent = {}
        free = None
        while queue and free is None:
            current = queue.popleft()
            for index in candidates[current]:
                if index in parent:
                    continue
                parent[index] = current
                if index not in owners:
                    free = index
                    break
                owner = owners[index]
                if owner not in visited:
                    queue.append(owner)
                    visited.add(owner)

        # Walk back from the free reference, reassigning one pair at a time.
        while free is not None:
            current = parent[free]
            owners[free] = current
            previous = matched.get(current)
            matched[current] = free
            free = previous
    return matched


def with_control_aliases(controls: list[Reference]) -> list[Reference]:
    database = load_object(TRAINING / "vulnerability-database" / "vulnerabilities.json")
    aliases = defaultdict(list)
    for entry in database["vulnerabilities"]:
        advisory_ids = (entry["id"], *entry["aliases"])
        for advisory in advisory_ids:
            aliases[(entry["group"], entry["artifact"], advisory)].extend(advisory_ids)

    expanded = []
    for control in controls:
        finding = control.finding
        if finding.dependency is not None:
            group, artifact, _ = finding.dependency
            related = [
                item for advisory in finding.advisories
                for item in aliases[(group, artifact, advisory)]
            ]
            finding = replace(finding, advisories=(*finding.advisories, *related))
        expanded.append(Reference(control.id, finding))
    return expanded


TRAINING_CODE_TRAPS = (
    ("Т-01", "src/main/kotlin/lab/servicedesk/config/RepairAccounts.kt", 17),
    ("Т-02", "src/main/kotlin/lab/servicedesk/integration/LegacyIntake.kt", 31),
)
TRAINING_TRANSITIVE = {("org.yaml", "snakeyaml"), ("org.jetbrains.kotlin", "kotlin-stdlib")}


def training_trap_hits(findings: list[Finding]) -> list[tuple[str, int]]:
    hits = []
    for index, finding in enumerate(findings):
        if finding.category == "SECRET" and finding.lines is not None:
            for trap_id, path, line in TRAINING_CODE_TRAPS:
                if finding.path == path and overlap(finding.lines, (line, line)):
                    hits.append((trap_id, index))
        if finding.dependency is not None and finding.dependency[:2] in TRAINING_TRANSITIVE:
            hits.append(("Т-03", index))
    return sorted(hits)


def breakdown(
    findings: list[Finding], truth: list[Reference], matched: dict[int, int]
) -> tuple[Metrics, list[list[str]], list[list[str]]]:
    predicted = Counter((finding.category, finding.kind) for finding in findings)
    expected = Counter((row.finding.category, row.finding.kind) for row in truth)
    true_positive = Counter((findings[index].category, findings[index].kind) for index in matched)

    by_class = []
    by_category = []
    for category in CATEGORIES:
        kinds = sorted(kind for group, kind in predicted.keys() | expected.keys() if group == category)
        category_metrics = Metrics(0, 0, 0)
        for kind in kinds:
            key = (category, kind)
            tp = true_positive[key]
            metrics = Metrics(tp, predicted[key] - tp, expected[key] - tp)
            by_class.append([category, escape(kind), *metrics.row()])
            category_metrics = Metrics(*(sum(pair) for pair in zip(category_metrics, metrics)))
        by_category.append([category, *category_metrics.row()])

    tp = len(matched)
    return Metrics(tp, len(findings) - tp, len(truth) - tp), by_category, by_class


def escape(value: str) -> str:
    # Keep report metadata inside its Markdown row even when it contains markup.
    escaped = []
    for char in value:
        if char == "|":
            escaped.append("&#124;")
        elif char in "\\\u0060*_{}[]()<>#!~&":
            escaped.append(f"&#{ord(char)};")
        elif not char.isprintable():
            escaped.append(" ")
        else:
            escaped.append(char)
    return "".join(escaped)


def describe(finding: Finding) -> str:
    path = escape(finding.path)
    if finding.lines is not None:
        start, end = finding.lines
        lines = str(start) if start == end else f"{start}–{end}"
        return f"{finding.category} {escape(finding.kind)} · {path}:{lines}"
    assert finding.dependency is not None
    coordinates = escape(":".join(finding.dependency))
    advisories = ", ".join(escape(item) for item in finding.advisories)
    return f"SCA {coordinates} · {advisories} · {path}"


def table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return ["Нет."]
    return [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
        *["| " + " | ".join(row) + " |" for row in rows],
    ]


def render(
    findings: list[Finding], truth: list[Reference], controls: list[Reference],
    organizer_truth: bool,
) -> str:
    matched = maximum_matching(findings, truth)
    found = set(matched.values())
    total, by_category, by_class = breakdown(findings, truth, matched)
    extras = [[str(index + 1), describe(finding)]
              for index, finding in enumerate(findings) if index not in matched]
    missed = [[escape(row.id), describe(row.finding)]
              for index, row in enumerate(truth) if index not in found]
    explicit = [(control.id, index) for control in controls
                for index, finding in enumerate(findings) if match(finding, control.finding)]
    implicit = training_trap_hits(findings) if organizer_truth else []
    metrics_headers = ["TP", "FP", "FN", "Precision", "Recall"]

    sections = [
        ["# Сверка отчёта", "", f"Найдено **{total.tp}/{len(truth)}** ожидаемых находок."],
        table(["Срез", *metrics_headers], [["Итого", *total.row()], *by_category]),
        ["## По классам", "", *table(["Категория", "Класс", *metrics_headers], by_class)],
        ["## Лишние находки", "", *table(["№ в отчёте", "Находка"], extras)],
        ["## Пропуски", "", *table(["ID эталона", "Находка"], missed)],
    ]
    for label, hits, count in (
        ("Контроли эталона", explicit, len(controls)),
        ("Неявные ловушки", implicit, len(TRAINING_CODE_TRAPS) + 1 if organizer_truth else 0),
    ):
        rows = [[escape(control_id), str(index + 1), describe(findings[index])]
                for control_id, index in hits]
        hit_controls = len({control_id for control_id, _ in hits})
        sections.append([
            f"## {label}", "",
            f"Затронуто **{hit_controls}/{count}**, срабатываний **{len(hits)}**.", "",
            *table(["ID", "№ в отчёте", "Находка"], rows),
        ])
    return "\n\n".join("\n".join(section) for section in sections) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="JSON-отчёт анализаторов")
    parser.add_argument("--truth", type=Path, default=DEFAULT_TRUTH, help="JSON-эталон")
    parser.add_argument("--markdown", type=Path, help="сохранить результаты в Markdown")
    args = parser.parse_args(argv)

    try:
        report = load_rows(
            args.report, load_object(args.report), "findings",
            lambda row: parse_finding(row, reference=False),
        )
        truth_file = load_object(args.truth)
        truth = load_rows(args.truth, truth_file, "findings", parse_reference)
        controls = load_rows(args.truth, truth_file, "controls", parse_reference)
        ids = [entry.id for entry in (*truth, *controls)]
        if len(set(ids)) != len(ids):
            raise InputError(f"{args.truth}: ID записей эталона должны быть уникальными")
        organizer_truth = args.truth.resolve() == DEFAULT_TRUTH.resolve()
        if organizer_truth:
            controls = with_control_aliases(controls)

        output = render(report, truth, controls, organizer_truth)
        if args.markdown:
            target = args.markdown.resolve()
            input_paths = (args.report.resolve(), args.truth.resolve())
            if (target.is_relative_to(TRAINING.resolve()) or target in input_paths
                    or (target.exists() and any(target.samefile(path) for path in input_paths))):
                raise InputError("выходной Markdown не должен перезаписывать входные файлы или учебный набор")
            target.write_text(output, encoding="utf-8", newline="\n")
    except (InputError, OSError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 2

    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
