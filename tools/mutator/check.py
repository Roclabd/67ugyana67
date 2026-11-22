#!/usr/bin/env python3
"""Run generated SECRET/SCA fixtures against a local packaged application."""

import argparse
import base64
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid
import zipfile

from generate import VARIANTS


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "evaluator"))
from evaluate import breakdown, load_object, load_rows, match, maximum_matching, parse_finding, parse_reference


class LocalApp:
    def __init__(self, port):
        self.base = f"http://127.0.0.1:{port}/api"

    def request(self, path, *, body=None, data=None, headers=None):
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers = {"Content-Type": "application/json"}
        request = Request(self.base + path, data=data, headers=headers or {})
        with urlopen(request, timeout=10) as response:
            return json.load(response)

    def create_workflow(self, catalog):
        trigger = next(node for node in catalog if node["type"] == "trigger.manual")
        nodes = [
            ("start", "trigger.manual"), ("archive", "source.archive"), ("parse", "analyzer.parse"),
            ("secret", "analyzer.secret"), ("sca", "analyzer.sca"),
        ]
        links = [
            ("start", trigger["outputs"][0]["name"], "archive", "trigger"),
            ("archive", "workspace", "parse", "workspace"),
            ("parse", "model", "secret", "model"),
            ("parse", "model", "sca", "model"),
        ]
        return self.request("/workflows", body={
            "name": "C7: локальные тестовые вариации",
            "nodes": [{"id": node, "type": kind} for node, kind in nodes],
            "edges": [
                {"id": f"e{index}", "from": {"node": source, "port": out_port},
                 "to": {"node": target, "port": in_port}}
                for index, (source, out_port, target, in_port) in enumerate(links, 1)
            ],
        })["id"]

    def scan(self, workflow, project, *, include_coverage=False):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for file in sorted(project.rglob("*")):
                if file.is_file():
                    output.write(file, file.relative_to(project).as_posix())
        boundary = "fixture-" + uuid.uuid4().hex
        prefix = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="fixture.zip"\r\n'
                  "Content-Type: application/zip\r\n\r\n").encode("ascii")
        content = prefix + archive.getvalue() + f"\r\n--{boundary}--\r\n".encode("ascii")
        upload = self.request("/uploads", data=content, headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        })
        run_id = self.request(f"/workflows/{workflow}/run", body={
            "source": {"kind": "upload", "uploadId": upload["uploadId"]},
        })["runId"]
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            run = self.request(f"/runs/{run_id}")
            if run["status"] == "FAILED":
                raise RuntimeError("Запуск анализаторов завершился ошибкой")
            if run["status"] != "RUNNING":
                report = self.request(f"/runs/{run_id}/report.json")
                if include_coverage:
                    report["coverage"] = run["report"]["coverage"]
                return run["coverageStatus"], report
            time.sleep(0.25)
        raise RuntimeError("Не удалось дождаться результата")


def score(variant, status, report):
    truth_file = variant / "truth.json"
    truth_object = load_object(truth_file)
    truth = load_rows(truth_file, truth_object, "findings", parse_reference)
    controls = load_rows(truth_file, truth_object, "controls", parse_reference)
    findings = load_rows(variant / "project", report, "findings", lambda row: parse_finding(row, reference=False))
    paired = maximum_matching(findings, truth)
    total, categories, _ = breakdown(findings, truth, paired)
    hit_controls = sum(any(match(finding, control.finding) for finding in findings) for control in controls)
    expected_coverage = truth_object.get("coverageStatus", "COMPLETE")
    by_category = {row[0]: row[1:] for row in categories}
    return total, by_category, hit_controls, len(controls), status == expected_coverage


def score_attention(variant, report):
    truth = load_object(variant / "truth.json")
    if "attention" not in truth:
        return "-", []

    expected = [dict(row, value=row.get("value") or secret_value(variant, row)) for row in truth["attention"]]
    problems = attention_problems(expected, report.get("findings", []), json.dumps(report, ensure_ascii=False))
    return f"{len(expected) - len(problems)}/{len(expected)}", problems


def secret_value(variant, row):
    """Значение секрета из строки фикстуры (`NAME=value`): оно не должно попасть в отчёт."""
    try:
        line = (variant / "project" / row["path"]).read_text(encoding="utf-8").splitlines()[row["line"] - 1]
    except (OSError, IndexError):
        return None
    return line.partition("=")[2].strip().strip("\"'") or None


def finding_class(item):
    return item.get("class") or str(item.get("rule", "")).removeprefix("secret.")


def is_test_finding(item):
    """Находка в тестовом каталоге. Пометка «(тестовый код)» есть только во внутреннем отчёте, в report.json её нет."""
    parts = str(item.get("path", "")).lower().split("/")
    return any(part in ("test", "tests", "testfixtures", "integrationtest", "androidtest") for part in parts[:-1])


def attention_problems(expected, findings, report_text=""):
    """Тестовый код остаётся находкой: класс, место, LOW и отсутствие значения секрета в отчёте."""
    problems = []
    for row in expected:
        label = f"{row['path']}:{row['line']} ({row['rule']})"
        wanted = str(row["rule"]).removeprefix("secret.")
        found = [item for item in findings if item.get("path") == row["path"]
                 and item.get("line") == row["line"] and finding_class(item) == wanted]
        if not found:
            problems.append(f"Нет находки в тестовом коде в {label}")
            continue
        item = found[0]
        if item.get("severity") != "LOW":
            problems.append(f"Находка в тестовом коде должна быть LOW: {label}, получено {item.get('severity')}")
        if item.get("secretMasked", "****") != "****":
            problems.append(f"Значение секрета не замаскировано в {label}")
        if row.get("value") and row["value"] in report_text:
            problems.append(f"Значение секрета попало в отчёт в {label}")
    marked = {(item.get("path"), item.get("line"), finding_class(item)) for item in findings if is_test_finding(item)}
    wanted_rows = {(row["path"], row["line"], str(row["rule"]).removeprefix("secret.")) for row in expected}
    problems.extend(f"Лишняя находка в тестовом коде в {path}:{line} ({kind})" for path, line, kind in sorted(marked - wanted_rows))
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", type=Path, required=True, help="Путь к JAR, собранному задачей bootJar")
    parser.add_argument("--java", default="java", help="Команда Java 21 или путь к ней")
    parser.add_argument("--variant", choices=VARIANTS, help="Проверить только выбранную вариацию")
    args = parser.parse_args()
    jar = args.jar.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="cg-variants-") as name:
        working = Path(name)
        variants = working / "variants"
        command = [sys.executable, "-B", str(Path(__file__).with_name("generate.py")), "--output", str(variants)]
        if args.variant:
            command += ["--variant", args.variant]
        subprocess.run(command, check=True, capture_output=True)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with (working / "server.log").open("wb") as log:
            env = dict(os.environ, APP_BIND_ADDRESS="127.0.0.1", PORT=str(port),
                       APP_SECRETS_KEY=base64.b64encode(os.urandom(32)).decode("ascii"))
            app = subprocess.Popen([args.java, "-jar", str(jar)], cwd=working,
                                   env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                client = LocalApp(port)
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    if app.poll() is not None:
                        raise RuntimeError("Приложение завершилось до запуска API")
                    try:
                        catalog = client.request("/nodes")
                        break
                    except URLError:
                        time.sleep(0.3)
                else:
                    raise RuntimeError("API не запустился за 45 секунд")
                workflow = client.create_workflow(catalog)
                print("| Вариация | SECRET | SCA | FP | FN | Контроли | «Обратите внимание» | Покрытие |")
                print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
                failed = False
                for variant in sorted(variants.iterdir()):
                    status, report = client.scan(workflow, variant / "project", include_coverage=True)
                    total, categories, hits, controls, coverage_ok = score(variant, status, report)
                    attention, problems = score_attention(variant, report)
                    secret_count = categories["SECRET"][0]
                    sca_count = categories["SCA"][0]
                    coverage_label = status if coverage_ok else f"{status} (расхождение)"
                    print(f"| {variant.name} | {secret_count} | {sca_count} | {total.fp} | {total.fn} | "
                          f"{hits}/{controls} | {attention} | {coverage_label} |")
                    for problem in problems:
                        print(f"{variant.name}: {problem}", file=sys.stderr)
                    failed |= bool(total.fp or total.fn or hits or problems or not coverage_ok)
                return int(failed)
            finally:
                app.terminate()
                try:
                    app.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    app.kill()
                    app.wait()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HTTPError as error:
        print(f"Ошибка локального API: HTTP {error.code} ({error.url})", file=sys.stderr)
        raise SystemExit(2)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"Ошибка прогона: {error}", file=sys.stderr)
        raise SystemExit(2)
