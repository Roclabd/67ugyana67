#!/usr/bin/env python3
"""Сквозная проверка точности: собранное приложение, полный граф SECRET + SCA + SAST, сверка evaluator'ом.

Корпуса:
  - training     — учебный проект авторов набора и их эталон (все категории, контроли);
  - c7           — вариации SECRET/SCA из tools/mutator (их эталон описывает только SECRET и SCA);
  - sast         — вариации SAST из src/test/resources/variants (эталон описывает только SAST).
Каждый корпус оценивается только по категориям своего эталона: находки других категорий в нём не размечены.

Запуск из корня репозитория (нужен собранный :backend:app:bootJar и Java 21):
  python -X utf8 -B backend/analyzers/sast/scripts/variants_e2e.py --jar backend/app/build/libs/app-0.1.0-SNAPSHOT.jar --java <java>
Код выхода 1 — есть FP, FN или срабатывания на контролях; 2 — ошибка прогона.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools" / "evaluator"))
sys.path.insert(0, str(ROOT / "tools" / "mutator"))
from evaluate import Metrics, breakdown, load_object, load_rows, match, maximum_matching, parse_finding, parse_reference  # noqa: E402
from check import LocalApp  # noqa: E402

SAST_VARIANTS = ROOT / "backend" / "analyzers" / "sast" / "src" / "test" / "resources" / "variants"
TRAINING = ROOT / "fixtures" / "training"


class FullScan(LocalApp):
    """Тот же клиент, что в tools/mutator/check.py, но граф с тремя анализаторами."""

    def create_workflow(self, catalog):
        trigger = next(node for node in catalog if node["type"] == "trigger.manual")
        nodes = [
            ("start", "trigger.manual"), ("archive", "source.archive"), ("parse", "analyzer.parse"),
            ("secret", "analyzer.secret"), ("sca", "analyzer.sca"), ("sast", "analyzer.sast"),
        ]
        links = [
            ("start", trigger["outputs"][0]["name"], "archive", "trigger"),
            ("archive", "workspace", "parse", "workspace"),
            ("parse", "model", "secret", "model"),
            ("parse", "model", "sca", "model"),
            ("parse", "model", "sast", "model"),
        ]
        return self.request("/workflows", body={
            "name": "D: сквозная точность SECRET + SCA + SAST",
            "nodes": [{"id": node, "type": kind} for node, kind in nodes],
            "edges": [
                {"id": f"e{index}", "from": {"node": source, "port": out_port}, "to": {"node": target, "port": in_port}}
                for index, (source, out_port, target, in_port) in enumerate(links, 1)
            ],
        })["id"]


def sast_truth(expected_file: Path, out_file: Path) -> Path:
    """expected.json вариации SAST → эталон формата evaluator'а (id + category)."""
    data = json.loads(expected_file.read_text(encoding="utf-8"))

    def rows(key):
        return [dict(row, id=f"{key}-{i}", category="SAST") for i, row in enumerate(data.get(key, []), 1)]

    out_file.write_text(json.dumps({"findings": rows("findings"), "controls": rows("controls")}, ensure_ascii=False), encoding="utf-8")
    return out_file


def score(truth_file: Path, report: dict, categories: set[str]):
    truth_object = load_object(truth_file)
    truth = [r for r in load_rows(truth_file, truth_object, "findings", parse_reference) if r.finding.category in categories]
    controls = [r for r in load_rows(truth_file, truth_object, "controls", parse_reference) if r.finding.category in categories]
    scoped = {"findings": [f for f in report.get("findings", []) if f.get("category") in categories]}
    findings = load_rows(truth_file, scoped, "findings", lambda row: parse_finding(row, reference=False))
    paired = maximum_matching(findings, truth)
    total, _, by_class = breakdown(findings, truth, paired)
    hits = sum(any(match(f, c.finding) for f in findings) for c in controls)
    return total, hits, len(controls), by_class


def corpora(work: Path):
    yield "training", "Service Desk (авторы набора)", TRAINING / "sample-project", TRAINING / "ground-truth" / "training-findings.json", {"SECRET", "SCA", "SAST"}
    c7 = work / "c7"
    subprocess.run([sys.executable, "-B", str(ROOT / "tools" / "mutator" / "generate.py"), "--output", str(c7)], check=True, capture_output=True)
    for variant in sorted(c7.iterdir()):
        yield "c7", variant.name, variant / "project", variant / "truth.json", {"SECRET", "SCA"}
    for variant in sorted(SAST_VARIANTS.iterdir()):
        if (variant / "expected.json").is_file():
            yield "sast", variant.name, variant, sast_truth(variant / "expected.json", work / f"truth-{variant.name}.json"), {"SAST"}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--jar", type=Path, required=True)
    parser.add_argument("--java", default="java")
    parser.add_argument("--markdown", type=Path, help="Сохранить таблицу в файл")
    args = parser.parse_args()
    jar = args.jar.resolve(strict=True)
    lines = []
    with tempfile.TemporaryDirectory(prefix="cg-e2e-") as name:
        work = Path(name)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with (work / "server.log").open("wb") as log:
            env = dict(os.environ, APP_BIND_ADDRESS="127.0.0.1", PORT=str(port), LLM_BASE_URL="",
                       APP_SECRETS_KEY=base64.b64encode(os.urandom(32)).decode("ascii"))
            app = subprocess.Popen([args.java, "-jar", str(jar)], cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                client = FullScan(port)
                deadline = time.monotonic() + 60
                while True:
                    if app.poll() is not None:
                        raise RuntimeError("Приложение завершилось до запуска API")
                    try:
                        catalog = client.request("/nodes")
                        break
                    except URLError:
                        if time.monotonic() > deadline:
                            raise RuntimeError("API не запустился за 60 секунд")
                        time.sleep(0.3)
                workflow = client.create_workflow(catalog)
                lines += ["| Корпус | Проект | Категории | TP | FP | FN | Контроли | Покрытие |",
                          "| --- | --- | --- | ---: | ---: | ---: | ---: | --- |"]
                sums: dict[str, list[int]] = {}
                misses = []
                failed = False
                for corpus, label, project, truth, cats in corpora(work):
                    status, report = client.scan(workflow, project)
                    total, hits, controls, by_class = score(truth, report, cats)
                    s = sums.setdefault(corpus, [0, 0, 0, 0, 0, 0])
                    for i, v in enumerate([total.tp, total.fp, total.fn, hits, controls, 1]):
                        s[i] += v
                    lines.append(f"| {corpus} | {label} | {'+'.join(sorted(cats))} | {total.tp} | {total.fp} | {total.fn} | {hits}/{controls} | {status} |")
                    if total.fp or total.fn or hits:
                        failed = True
                        misses.append(f"{label}: " + "; ".join(f"{row[0]} {row[1]} TP {row[2]} FP {row[3]} FN {row[4]}" for row in by_class if row[3] != "0" or row[4] != "0"))
                lines += ["", "| Корпус | Проектов | TP | FP | FN | Precision | Recall | Контроли |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
                for corpus, (tp, fp, fn, hits, controls, n) in sums.items():
                    m = Metrics(tp, fp, fn).row()
                    lines.append(f"| {corpus} | {n} | {tp} | {fp} | {fn} | {m[3]} | {m[4]} | {hits}/{controls} |")
                if misses:
                    lines += ["", "Расхождения:"] + [f"- {m}" for m in misses]
            finally:
                app.terminate()
                try:
                    app.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    app.kill()
                    app.wait()
    text = "\n".join(lines) + "\n"
    print(text)
    if args.markdown:
        args.markdown.write_text(text, encoding="utf-8")
    return int(failed)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"Ошибка прогона: {error}", file=sys.stderr)
        raise SystemExit(2)
