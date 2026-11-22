"""Проверка разбора «тестовых» находок в check.py без запуска приложения."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check

EXPECTED = [{"path": "src/test/.env", "line": 2, "rule": "secret.api-key", "reason": "test-source"}]


def finding(**changes):
    row = {"path": "src/test/.env", "line": 2, "rule": "secret.api-key", "severity": "LOW",
           "title": "Ключ API в исходниках (тестовый код)", "secretMasked": "****"}
    row.update(changes)
    return row


class AttentionTest(unittest.TestCase):
    def test_low_marked_masked_finding_passes(self):
        self.assertEqual([], check.attention_problems(EXPECTED, [finding()]))

    def test_missing_finding_fails(self):
        self.assertEqual(1, len(check.attention_problems(EXPECTED, [])))

    def test_wrong_severity_fails(self):
        self.assertTrue(check.attention_problems(EXPECTED, [finding(severity="MEDIUM")]))

    def test_report_without_internal_fields_passes(self):
        row = {"path": "src/test/.env", "line": 2, "class": "api-key", "severity": "LOW"}
        self.assertEqual([], check.attention_problems(EXPECTED, [row]))

    def test_unmasked_value_fails(self):
        self.assertTrue(check.attention_problems(EXPECTED, [finding(secretMasked="abc")]))

    def test_value_in_report_fails(self):
        expected = [dict(EXPECTED[0], value="fixture-secret-1")]
        self.assertTrue(check.attention_problems(expected, [finding()], "... fixture-secret-1 ..."))
        self.assertEqual([], check.attention_problems(expected, [finding()], "..."))

    def test_unexpected_test_finding_fails(self):
        extra = finding(line=9)
        self.assertTrue(check.attention_problems(EXPECTED, [finding(), extra]))


if __name__ == "__main__":
    unittest.main()
