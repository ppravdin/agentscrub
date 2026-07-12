"""Python wrapper around the Rampart ONNX PII model.

Loads `nationaldesignstudio/rampart` from Hugging Face, runs the q4 ONNX
token-classifier with onnxruntime, and adds deterministic recognizers for
structured PII (SSN, credit card, email, URL, IP address).

This is intentionally a standalone module so agentscrub can detect and redact
personal information (names, addresses, phones, government IDs, etc.) in
addition to the existing secret scanners (gitleaks, TruffleHog, Titus).
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort
from huggingface_hub import hf_hub_download
from transformers import AutoTokenizer

RAMPART_MODEL_ID = "nationaldesignstudio/rampart"
ONNX_FILE = "onnx/model_q4.onnx"
CONFIG_FILE = "config.json"

# Labels that are redacted by default in the official runtime.
DETERMINISTIC_LABELS = frozenset({"SSN", "CREDIT_CARD", "EMAIL", "URL", "IP_ADDRESS"})
MODEL_LABELS = frozenset({
    "GIVEN_NAME", "SURNAME", "PHONE", "TAX_ID", "BANK_ACCOUNT", "ROUTING_NUMBER",
    "GOVERNMENT_ID", "PASSPORT", "DRIVERS_LICENSE", "BUILDING_NUMBER",
    "STREET_NAME", "SECONDARY_ADDRESS", "EMAIL", "URL",
})
KEEP_LABELS = frozenset({"CITY", "STATE", "ZIP_CODE"})
ALL_REDACT_LABELS = DETERMINISTIC_LABELS | MODEL_LABELS

# Token-level BIO label IDs are read from the downloaded config at load time.


@dataclass
class Span:
    label: str
    start: int
    end: int
    text: str
    score: float = 1.0

    def __hash__(self) -> int:
        return hash((self.label, self.start, self.end, self.text))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Span):
            return NotImplemented
        return (self.label, self.start, self.end, self.text) == (
            other.label, other.start, other.end, other.text
        )


@dataclass
class ScrubResult:
    text: str
    placeholders: list[str] = field(default_factory=list)
    spans: list[Span] = field(default_factory=list)


class RampartPiiDetector:
    """Load and run the Rampart PII model in Python.

    Example:
        detector = RampartPiiDetector()
        result = detector.redact("My name is Alex Rivera and my SSN is 472-81-0094.")
        print(result.text)
        # -> "My name is [GIVEN_NAME_1] [SURNAME_1] and my SSN is [SSN_1]."
    """

    def __init__(
        self,
        model_id: str = RAMPART_MODEL_ID,
        device: str = "cpu",
        min_score: float = 0.4,
        keep_labels: set[str] | frozenset[str] | None = None,
        cache_dir: str | Path | None = None,
    ) -> None:
        self.model_id = model_id
        self.device = device
        self.min_score = min_score
        self.keep_labels = set(keep_labels) if keep_labels is not None else set(KEEP_LABELS)
        self.cache_dir = Path(cache_dir) if cache_dir else None

        self._tokenizer: Any | None = None
        self._session: ort.InferenceSession | None = None
        self._id2label: dict[int, str] = {}
        self._placeholders: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}

    def _ensure_loaded(self) -> None:
        if self._session is not None:
            return

        local_files_only = False
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

        config_path = hf_hub_download(
            repo_id=self.model_id,
            filename=CONFIG_FILE,
            cache_dir=self.cache_dir,
            local_files_only=local_files_only,
        )
        with open(config_path) as fh:
            config = json.load(fh)
        self._id2label = {int(k): v for k, v in config["id2label"].items()}

        self._tokenizer = AutoTokenizer.from_pretrained(
            self.model_id,
            cache_dir=self.cache_dir,
            local_files_only=local_files_only,
        )

        model_path = hf_hub_download(
            repo_id=self.model_id,
            filename=ONNX_FILE,
            cache_dir=self.cache_dir,
            local_files_only=local_files_only,
        )
        providers = ["CUDAExecutionProvider", "CPUExecutionProvider"] if self.device == "cuda" else ["CPUExecutionProvider"]
        self._session = ort.InferenceSession(model_path, providers=providers)

    def _normalize(self, text: str) -> str:
        """Match the runtime normalization: lowercase, NFKD, strip combining marks."""
        return self._normalize_with_map(text)[0]

    @staticmethod
    def _normalize_with_map(text: str) -> tuple[str, list[int]]:
        """Return normalized text plus original index for every normalized char."""
        normalized: list[str] = []
        offsets: list[int] = []
        for original_index, char in enumerate(text):
            piece = "".join(
                c for c in unicodedata.normalize("NFKD", char.lower())
                if unicodedata.category(c) != "Mn"
            )
            normalized.append(piece)
            offsets.extend([original_index] * len(piece))
        return "".join(normalized), offsets

    def _detect_deterministic(self, text: str) -> list[Span]:
        """High-recall regex recognizers for structured PII."""
        spans: list[Span] = []

        # Email addresses.
        for m in re.finditer(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text
        ):
            spans.append(Span("EMAIL", m.start(), m.end(), m.group()))

        # URLs (http/https/ftp).
        for m in re.finditer(
            r"https?://[^\s\"'<>]+|ftp://[^\s\"'<>]+", text
        ):
            value = m.group().rstrip(".,;:!?]")
            while value.endswith(")") and value.count("(") < value.count(")"):
                value = value[:-1]
            spans.append(Span("URL", m.start(), m.start() + len(value), value))

        # IPv4 / IPv6 / MAC (simplified; good enough for typical logs).
        for m in re.finditer(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text
        ):
            if all(0 <= int(x) <= 255 for x in m.group().split(".")):
                spans.append(Span("IP_ADDRESS", m.start(), m.end(), m.group()))

        # SSN: XXX-XX-XXXX or XXX XX XXXX.
        for m in re.finditer(
            r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b", text
        ):
            spans.append(Span("SSN", m.start(), m.end(), m.group()))

        # Credit card: 13-19 digits with optional separators; Luhn-validated.
        for m in re.finditer(
            r"\b(?:\d[ -]*?){13,19}\b", text
        ):
            digits = re.sub(r"\D", "", m.group())
            if 13 <= len(digits) <= 19 and self._luhn_valid(digits):
                spans.append(Span("CREDIT_CARD", m.start(), m.end(), m.group()))

        return spans

    @staticmethod
    def _luhn_valid(digits: str) -> bool:
        if not digits.isdigit():
            return False
        total = 0
        reverse = digits[::-1]
        for i, ch in enumerate(reverse):
            n = int(ch)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    def _detect_model(self, text: str) -> list[Span]:
        """Run the ONNX token classifier and decode BIO spans."""
        self._ensure_loaded()
        assert self._tokenizer is not None and self._session is not None

        if not text:
            return []
        normalized, normalized_to_original = self._normalize_with_map(text)
        enc = self._tokenizer(
            normalized,
            return_tensors="np",
            truncation=True,
            max_length=512,
            stride=64,
            padding="max_length",
            return_overflowing_tokens=True,
            return_offsets_mapping=True,
            return_special_tokens_mask=True,
        )

        spans: list[Span] = []
        window_count = enc["input_ids"].shape[0]
        for window_index in range(window_count):
            inputs = {
                "input_ids": enc["input_ids"][window_index:window_index + 1].astype(np.int64),
                "attention_mask": enc["attention_mask"][window_index:window_index + 1].astype(np.int64),
            }
            if "token_type_ids" in enc:
                inputs["token_type_ids"] = enc["token_type_ids"][window_index:window_index + 1].astype(np.int64)

            outputs = self._session.run(None, inputs)
            logits = outputs[0][0]  # (seq_len, num_labels)
            logits -= np.max(logits, axis=-1, keepdims=True)
            probabilities = np.exp(logits)
            probabilities /= np.sum(probabilities, axis=-1, keepdims=True)
            label_ids = np.argmax(probabilities, axis=-1)
            scores = np.max(probabilities, axis=-1)
            offsets = enc["offset_mapping"][window_index]
            special_mask = enc["special_tokens_mask"][window_index]

            current_label: str | None = None
            current_start: int | None = None
            current_end: int | None = None
            current_score_sum = 0.0
            current_count = 0

            def flush() -> None:
                nonlocal current_label, current_start, current_end
                nonlocal current_score_sum, current_count
                if current_label is None or current_start is None or current_end is None:
                    return
                if current_end > current_start:
                    spans.append(Span(
                        current_label,
                        current_start,
                        current_end,
                        normalized[current_start:current_end],
                        current_score_sum / current_count,
                    ))
                current_label = None
                current_start = None
                current_end = None
                current_score_sum = 0.0
                current_count = 0

            for i, (lid, offset, is_special) in enumerate(
                zip(label_ids, offsets, special_mask, strict=True)
            ):
                if is_special:
                    flush()
                    continue
                label = self._id2label.get(int(lid), "O")
                if label == "O" or "-" not in label or float(scores[i]) < self.min_score:
                    flush()
                    continue

                bio, entity = label.split("-", 1)
                start, end = int(offset[0]), int(offset[1])
                if end <= start:
                    continue
                if bio == "B" or entity != current_label:
                    flush()
                    current_label = entity
                    current_start = start
                    current_end = end
                    current_score_sum = float(scores[i])
                    current_count = 1
                else:
                    current_end = end
                    current_score_sum += float(scores[i])
                    current_count += 1
            flush()

        # Map normalized offsets back to original text offsets.
        result: list[Span] = []
        for span in spans:
            orig_start = self._map_offset(text, normalized, span.start, normalized_to_original)
            orig_end = self._map_offset(text, normalized, span.end, normalized_to_original)
            result.append(Span(span.label, orig_start, orig_end, text[orig_start:orig_end], span.score))
        return result

    @staticmethod
    def _map_offset(
        original: str,
        normalized: str,
        norm_index: int,
        normalized_to_original: list[int] | None = None,
    ) -> int:
        """Best-effort map from a normalized-string offset to the original string."""
        if norm_index <= 0:
            return 0
        if norm_index >= len(normalized):
            return len(original)
        if normalized_to_original is None:
            _, normalized_to_original = RampartPiiDetector._normalize_with_map(original)
        return normalized_to_original[norm_index]

    def detect(self, text: str) -> list[Span]:
        """Return all PII spans in `text`."""
        model_spans = self._detect_model(text)
        det_spans = self._detect_deterministic(text)

        # Merge: deterministic spans take precedence where they overlap.
        spans = list(det_spans)
        for ms in model_spans:
            if ms.label in self.keep_labels:
                continue
            if ms.label not in ALL_REDACT_LABELS:
                continue
            if not any(
                ds.start < ms.end and ds.end > ms.start and ds.label in DETERMINISTIC_LABELS
                for ds in det_spans
            ):
                spans.append(ms)

        # Deterministic recognizers win over model windows, then keep only one
        # span for overlapping model-window predictions.
        spans.sort(key=lambda s: (s.start, -(s.end - s.start)))
        deterministic_ids = {id(s) for s in det_spans}
        ordered = sorted(
            spans,
            key=lambda s: (
                0 if id(s) in deterministic_ids else 1,
                s.start,
                -(s.end - s.start),
                -s.score,
            ),
        )
        filtered: list[Span] = []
        for s in ordered:
            if any(existing.start < s.end and existing.end > s.start for existing in filtered):
                continue
            filtered.append(s)
        filtered.sort(key=lambda s: (s.start, s.end))
        return filtered

    def _placeholder_for(self, label: str, value: str) -> str:
        key = (label, value)
        if key not in self._placeholders:
            self._counters[label] = self._counters.get(label, 0) + 1
            self._placeholders[key] = f"[{label}_{self._counters[label]}]"
        return self._placeholders[key]

    def redact(self, text: str) -> ScrubResult:
        """Return text with PII replaced by stable placeholders."""
        spans = self.detect(text)
        # Replace right-to-left so offsets stay valid.
        out = text
        placeholders: list[str] = []
        for span in reversed(spans):
            ph = self._placeholder_for(span.label, span.text)
            placeholders.append(ph)
            out = out[: span.start] + ph + out[span.end :]
        placeholders.reverse()
        return ScrubResult(out, placeholders, spans)

    def proof(self, span: Span) -> str:
        """Safe one-line summary of a span without exposing its value."""
        h = hashlib.sha256(span.text.encode()).hexdigest()[:8]
        return f"{span.label} · #{h}"


# Convenience module-level singleton for quick use.
_default_detector: RampartPiiDetector | None = None


def _get_default() -> RampartPiiDetector:
    global _default_detector
    if _default_detector is None:
        _default_detector = RampartPiiDetector()
    return _default_detector


def detect_pii(text: str) -> list[Span]:
    return _get_default().detect(text)


def redact_pii(text: str) -> ScrubResult:
    return _get_default().redact(text)
