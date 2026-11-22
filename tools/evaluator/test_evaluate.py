import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from evaluate import DEFAULT_TRUTH, TRAINING, main


def prediction(row, advisory_index=0):
    keys = ["category", "path"]
    if row["category"] == "SCA":
        keys.extend(["group", "artifact", "version"])
        return {**{key: row[key] for key in keys}, "advisoryId": row["advisoryIds"][advisory_index]}
    keys.extend(["class", "line"])
    if "endLine" in row:
        keys.append("endLine")
    return {key: row[key] for key in keys}


def code(line, *, end=None, path="code.kt"):
    result = {"category": "SECRET", "class": "password", "path": path, "line": line}
    if end is not None:
        result["endLine"] = end
    return result


class EvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.training = json.loads(DEFAULT_TRUTH.read_text(encoding="utf-8"))

    def score(self, findings, *, truth=None, invalid=False):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            report = directory / "report.json"
            markdown = directory / "results.md"
            report.write_text(json.dumps({"findings": findings}), encoding="utf-8")
            argv = [str(report), "--markdown", str(markdown)]
            if truth is not None:
                truth_path = directory / "truth.json"
                truth_path.write_text(json.dumps(truth), encoding="utf-8")
                argv.extend(["--truth", str(truth_path)])
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = main(argv)
            if invalid:
                self.assertEqual(result, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertFalse(markdown.exists())
                return stderr.getvalue()
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertEqual(markdown.read_text(encoding="utf-8"), stdout.getvalue())
            return stdout.getvalue()

    def test_empty_and_example(self):
        self.assertIn("| Итого | 0 | 0 | 15 | — | 0.00% |", self.score([]))
        example = json.loads((TRAINING / "docs" / "training-result-example.json").read_text(
            encoding="utf-8"
        ))
        rendered = self.score(example["findings"])
        self.assertIn("| Итого | 3 | 0 | 12 | 100.00% | 20.00% |", rendered)
        self.assertIn("| SCA | known-vulnerable-dependency | 1 | 0 | 4 |", rendered)

    def test_all_training_findings_using_ghsa_and_inclusive_ranges(self):
        reports = [
            prediction(row, advisory_index=-1) for row in self.training["findings"]
        ]
        for finding in reports:
            finding["path"] = finding["path"].replace("/", "\\")
            if "endLine" in finding:
                finding["line"] = finding.pop("endLine")
        rendered = self.score(reports)
        self.assertIn("| Итого | 15 | 0 | 0 | 100.00% | 100.00% |", rendered)
        self.assertIn("**0/6**, срабатываний **0**", rendered)
        self.assertIn("**0/3**, срабатываний **0**", rendered)

    def test_overlapping_predictions_use_maximum_one_to_one_matching(self):
        truth = {"findings": [{"id": "one", **code(1)}, {"id": "two", **code(2)}]}
        reports = [code(1, end=2), code(1), code(1)]
        rendered = self.score(reports, truth=truth)
        self.assertIn("| Итого | 2 | 1 | 0 | 66.67% | 100.00% |", rendered)
        self.assertIn("| 3 | SECRET password", rendered)
        self.assertEqual(rendered, self.score(reports, truth=truth))

    def test_sca_alias_duplicates_and_literal_version(self):
        row = next(finding for finding in self.training["findings"] if finding["category"] == "SCA")
        truth = {"findings": [row]}
        first = prediction(row)
        alias = prediction(row, advisory_index=1)
        version = {**first, "version": row["version"] + ".0"}
        wrong_alias = {**first, "advisoryId": "UNKNOWN"}
        wrong_path = {**first, "path": "gradle.lockfile"}
        rendered = self.score([first, alias, version, wrong_alias, wrong_path], truth=truth)
        self.assertIn("| Итого | 1 | 4 | 0 | 20.00% | 100.00% |", rendered)

    def test_distinct_sca_advisories_for_a_single_package(self):
        first = next(row for row in self.training["findings"] if row["category"] == "SCA")
        second = {**first, "id": "second", "advisoryIds": ["CVE-2000-9999"]}
        rendered = self.score([prediction(first), prediction(second)], truth={"findings": [first, second]})
        self.assertIn("| Итого | 2 | 0 | 0 | 100.00% | 100.00% |", rendered)

    def test_case_and_alternate_locations_do_not_match(self):
        row = next(finding for finding in self.training["findings"]
                   if finding["category"] == "SAST" and finding["alternateLocations"])
        first = prediction(row)
        alternate = {**first, **row["alternateLocations"][0]}
        wrong_case = {**first, "path": first["path"].upper()}
        wrong_class = {**first, "class": first["class"].upper()}
        rendered = self.score([alternate, wrong_case, wrong_class], truth={"findings": [row]})
        self.assertIn("| Итого | 0 | 3 | 1 | 0.00% | 0.00% |", rendered)

    def test_training_controls_and_variant_isolation(self):
        reports = [prediction(row) for row in self.training["controls"]]
        reports[2]["advisoryId"] = "GHSA-j288-q9x7-2f5v"
        root = "src/main/kotlin/lab/servicedesk"
        reports.extend([
            code(17, path=f"{root}/config/RepairAccounts.kt"),
            code(31, path=f"{root}/integration/LegacyIntake.kt"),
            {"category": "SCA", "path": "gradle.lockfile", "group": "org.yaml",
             "artifact": "snakeyaml", "version": "2.5", "advisoryId": "GHSA-example"},
            {"category": "SCA", "path": "build.gradle.kts", "group": "org.jetbrains.kotlin",
             "artifact": "kotlin-stdlib", "version": "2.2.21", "advisoryId": "GHSA-example"},
        ])
        rendered = self.score(reports)
        self.assertIn("| Итого | 0 | 10 | 15 | 0.00% | 0.00% |", rendered)
        self.assertIn("**6/6**, срабатываний **6**", rendered)
        self.assertIn("**3/3**, срабатываний **4**", rendered)
        custom = {"dataset": "training", "findings": [], "controls": self.training["controls"][:1]}
        rendered = self.score(reports, truth=custom)
        self.assertIn("**1/1**, срабатываний **1**", rendered)
        self.assertIn("**0/0**, срабатываний **0**", rendered)

    def test_controls_are_reported_independently_of_overlapping_positive(self):
        row = code(1)
        control = code(2)
        truth = {"findings": [{"id": "one", **row}], "controls": [{"id": "control", **control}]}
        rendered = self.score([code(1, end=2)], truth=truth)
        self.assertIn("| Итого | 1 | 0 | 0 | 100.00% | 100.00% |", rendered)
        self.assertIn("| control | 1 |", rendered)

    def test_invalid_scoring_fields_fail_and_ignore_optional_payload(self):
        self.assertIn("line", self.score([code(True)], invalid=True))
        self.assertIn("endLine", self.score([code(1, end=16)], invalid=True))
        self.assertIn("endLine", self.score([code(2, end=1)], invalid=True))
        self.assertIn("path", self.score([code(1, path="dir/../code.kt")], invalid=True))
        self.assertIn("path", self.score([code(1, path="dir/\x00code.kt")], invalid=True))
        rendered = self.score([{**code(1), "description": "DO-NOT-PRINT"}], truth={"findings": []})
        self.assertNotIn("DO-NOT-PRINT", rendered)


if __name__ == "__main__":
    unittest.main()
