import unittest

from scripts.all_contracts_report import classify_result, summarize


class AllContractsReportTests(unittest.TestCase):
    def test_classification_uses_readable_view_and_unique_version(self):
        result = {
            "success": True,
            "decompilation": {"reconstruction_mode": "assembly", "recompiles": True,
                              "exact_hash_match": True},
            "readable": {"decompilation": {"reconstruction_mode": "structured",
                                             "recompiles": True, "exact_hash_match": False}},
            "debug": {"compiler_candidates": [
                {"version": "0.4.4", "score": 1.0},
                {"version": "0.3.0", "score": 0.5},
            ]},
        }
        classified = classify_result(result, "0.4.4")
        self.assertTrue(classified["fully_decompiled"])
        self.assertTrue(classified["compiler_version_correct"])
        self.assertFalse(classified["code_hash_match"])

    def test_tied_versions_are_not_reported_as_correct(self):
        result = {"success": True, "decompilation": {"reconstruction_mode": "structured",
                  "recompiles": True, "exact_hash_match": True}, "debug": {
                  "compiler_candidates": [{"version": "0.4.4", "score": 1.0},
                                           {"version": "0.3.0", "score": 1.0}]}}
        classified = classify_result(result, "0.4.4")
        self.assertFalse(classified["compiler_version_correct"])
        self.assertTrue(classified["compiler_version_in_top_tie"])

    def test_summary_keeps_failures_in_denominator(self):
        rows = [
            {"metadata_version": "0.4.4", "input_compiled": True,
             "decompilation_succeeded": True, **dict.fromkeys(
                 ("fully_decompiled", "compiler_version_correct", "code_hash_match"), True)},
            {"metadata_version": "0.4.4", "input_compiled": False,
             "decompilation_succeeded": False, "failure_stage": "input_compilation",
             **dict.fromkeys(("fully_decompiled", "compiler_version_correct", "code_hash_match"), False)},
        ]
        summary = summarize(rows)
        self.assertEqual(summary["contracts"], 2)
        self.assertEqual(summary["totals"]["fully_decompiled"], 1)
        self.assertEqual(sum(row["contracts"] for row in summary["combinations"]), 2)


if __name__ == "__main__":
    unittest.main()
