"""Measure the corpus: hidden text withheld, visible attacks kept, benign text preserved."""

import json
from pathlib import Path

from sanitize_skill.pipeline import sanitize_bytes

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "corpus"


def evaluate(level: int = 2) -> dict:
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    groups = {"benign": [], "hidden": [], "visible_instruction": []}
    benign_mismatch = 0
    for case in manifest:
        data = (CORPUS / case["path"]).read_bytes()
        result = sanitize_bytes(data, filename=Path(case["path"]).name, level=level, locator=case["path"])
        blob = json.dumps(result.model, ensure_ascii=False)
        present = all(text in blob for text in case["expect_in_model"])
        absent = all(text not in blob for text in case["expect_absent"])
        groups[case["group"]].append({"id": case["id"], "present": present, "absent": absent, "verdict": result.evidence["verdict"]})
        if case["group"] == "benign" and result.evidence["verdict"] == "hidden_mismatch":
            benign_mismatch += 1
    hidden = groups["hidden"]
    visible = groups["visible_instruction"]
    benign = groups["benign"]
    visible_l4 = 0
    if level == 2:
        for case in manifest:
            if case["group"] != "visible_instruction":
                continue
            data = (CORPUS / case["path"]).read_bytes()
            result = sanitize_bytes(data, filename=Path(case["path"]).name, level=4, locator=case["path"])
            if any(text in result.visible_text for text in case["expect_in_model"] if "ignore previous" in text):
                visible_l4 += 1
    return {
        "level": level,
        "hidden_total": len(hidden),
        "hidden_caught": sum(1 for item in hidden if item["absent"] and item["verdict"] == "hidden_mismatch"),
        "visible_total": len(visible),
        "visible_reached_model": sum(1 for item in visible if item["present"]),
        "visible_reached_model_level_4": visible_l4,
        "benign_total": len(benign),
        "benign_spoiled": sum(1 for item in benign if not item["present"]),
        "benign_mismatch": benign_mismatch,
        "cases": {key: value for key, value in groups.items()},
    }


def main() -> None:
    metrics = evaluate()
    (CORPUS / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"hidden {metrics['hidden_caught']}/{metrics['hidden_total']}; "
        f"visible_in_model {metrics['visible_reached_model']}/{metrics['visible_total']}; "
        f"benign_spoiled {metrics['benign_spoiled']}/{metrics['benign_total']}; "
        f"benign_mismatch {metrics['benign_mismatch']}; "
        f"visible_in_model_l4 {metrics['visible_reached_model_level_4']}/{metrics['visible_total']}"
    )


if __name__ == "__main__":
    main()
