import json
from pathlib import Path

from sanitize_skill.eval_corpus import evaluate

ROOT = Path(__file__).resolve().parents[1]


def test_skill_copies_match():
    assert (ROOT / "SKILL.md").read_text(encoding="utf-8") == (ROOT / ".cursor/skills/sanitize/SKILL.md").read_text(encoding="utf-8")
    assert (ROOT / "reference.md").read_text(encoding="utf-8") == (ROOT / ".cursor/skills/sanitize/reference.md").read_text(encoding="utf-8")


def test_committed_corpus_metrics_match_a_fresh_run():
    fresh = evaluate()
    committed = json.loads((ROOT / "corpus" / "metrics.json").read_text(encoding="utf-8"))
    assert fresh["hidden_caught"] == committed["hidden_caught"] == 13
    assert fresh["hidden_total"] == committed["hidden_total"] == 24
    assert fresh["visible_reached_model"] == committed["visible_reached_model"] == 4
    assert fresh["benign_spoiled"] == committed["benign_spoiled"] == 0
    assert fresh["benign_total"] == 15
    assert fresh["benign_mismatch"] == 1
    assert fresh["visible_reached_model_level_4"] == 0
    homoglyphs = [item for item in fresh["cases"]["hidden"] if str(item["id"]).startswith("homoglyph")]
    assert len(homoglyphs) == 5
    assert all(item["homoglyph"] and item["present"] and item["verdict"] == "marked" for item in homoglyphs)
    assert all(not item["homoglyph"] for item in fresh["cases"]["benign"])
