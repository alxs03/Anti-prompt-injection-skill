import importlib
import os


def classify_text(text: str) -> dict:
    """Optional hook. The result is evidence only and never changes model text.

    Set SANITIZE_CLASSIFIER to ``module:function``. The function receives a
    text chunk and returns ``{"label": str, "score": float}``.
    """
    spec = os.environ.get("SANITIZE_CLASSIFIER", "").strip()
    if not spec:
        return {"status": "skipped", "reason": "SANITIZE_CLASSIFIER is not set"}
    if ":" not in spec:
        return {"status": "error", "reason": "SANITIZE_CLASSIFIER must be module:function"}
    module_name, func_name = spec.split(":", 1)
    try:
        func = getattr(importlib.import_module(module_name), func_name)
    except (ImportError, AttributeError):
        return {"status": "error", "reason": "classifier hook was not importable"}

    chunks = _chunks(text)
    best: float | None = None
    label = ""
    for chunk in chunks:
        try:
            raw = func(chunk)
        except Exception:
            return {"status": "error", "reason": "classifier failed"}
        if not isinstance(raw, dict):
            return {"status": "error", "reason": "classifier returned an unexpected value"}
        if not label and raw.get("label"):
            label = str(raw["label"])[:80]
        score = raw.get("score")
        try:
            score_value = None if score is None else float(score)
        except (TypeError, ValueError):
            score_value = None
        if score_value is not None and (best is None or score_value > best):
            best = score_value
    return {"status": "ok", "label": label, "score": best, "chunks": len(chunks)}


def _chunks(text: str, size: int = 4000, limit: int = 32) -> list[str]:
    if not text:
        return [""]
    pieces = [text[index : index + size] for index in range(0, len(text), size)]
    return pieces[:limit]
