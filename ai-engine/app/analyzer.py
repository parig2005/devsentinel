"""ML inference pipeline for DevSentinel AI.

Design notes for the viva
-------------------------
CodeBERT (`microsoft/codebert-base`) is a *base* encoder — it has no
classification head trained on vulnerability labels, so out of the box it
produces embeddings, not verdicts. Two honest options:

  A. Fine-tune a classification head on a labelled dataset (Devign, Juliet,
     Big-Vul). Best results, but needs GPU time and a labelled corpus.
  B. Use the encoder for embeddings + a rule-assisted decision layer, which is
     what this module implements by default.

This file implements (B) and leaves a clearly marked seam for (A). Be upfront
about this in your viva — examiners respect "here is what is real inference and
here is what is a rule layer" far more than a black box you cannot explain.

The rule layer is genuinely useful: it produces deterministic, explainable
findings, and the embedding similarity score from the model is used to rank and
weight them.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known vulnerability signatures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Signature:
    """A single detectable weakness with its metadata and remediation."""

    vulnerability_type: str
    pattern: re.Pattern
    severity: float                 # 0.0 - 10.0
    owasp_category: Optional[str]
    description: str
    suggested_fix: str
    # A short natural-language description of the weakness. Used as the
    # "reference text" the model embeds the snippet against.
    semantic_anchor: str


SIGNATURES: list[Signature] = [
    Signature(
        vulnerability_type="SQL_INJECTION",
        # Matches an exec-style call whose argument contains both a SQL keyword
        # and a '+' concatenation. Deliberately permissive about quotes inside
        # the SQL text itself (e.g. WHERE name = '" + name + "').
        pattern=re.compile(
            r"(executeQuery|executeUpdate|execute|createQuery|createNativeQuery)\s*\("
            r"[^;]*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;]*\+",
            re.IGNORECASE | re.DOTALL,
        ),
        severity=9.0,
        owasp_category="A03:2021-Injection",
        description=(
            "A SQL statement is assembled by concatenating a string literal with a "
            "variable and handed to the JDBC driver. If any part of that variable "
            "comes from user input, an attacker can change the meaning of the query "
            "(bypass authentication, dump tables, or drop them)."
        ),
        suggested_fix=(
            "PreparedStatement ps = connection.prepareStatement(\n"
            "        \"SELECT * FROM users WHERE username = ?\");\n"
            "ps.setString(1, username);\n"
            "try (ResultSet rs = ps.executeQuery()) {\n"
            "    // consume results\n"
            "}"
        ),
        semantic_anchor="building a SQL query by concatenating untrusted user input into a string",
    ),
    Signature(
        vulnerability_type="HARDCODED_SECRET",
        # \w* on both sides so camelCase names like dbPassword / apiKeyValue match,
        # not just identifiers that start with the keyword.
        pattern=re.compile(
            r"(?i)\w*(password|passwd|pwd|secret|api_?key|token|credential)\w*\s*=\s*\"[^\"]{3,}\""
        ),
        severity=7.5,
        owasp_category="A07:2021-Identification and Authentication Failures",
        description=(
            "A credential is embedded directly in the source as a string literal. It "
            "will be present in version control history and recoverable from the "
            "compiled .class file with any decompiler."
        ),
        suggested_fix=(
            "// Read from the environment or an externalized config source\n"
            "private static final String DB_PASSWORD = System.getenv(\"DB_PASSWORD\");\n"
            "\n"
            "// In Spring Boot, prefer:\n"
            "@Value(\"${app.db.password}\")\n"
            "private String dbPassword;"
        ),
        semantic_anchor="a password or API key written directly into the source code as a literal",
    ),
    Signature(
        vulnerability_type="WEAK_CRYPTOGRAPHY",
        pattern=re.compile(
            r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-?1)\"\s*\)"
            r"|Cipher\.getInstance\s*\(\s*\"DES",
            re.IGNORECASE,
        ),
        severity=7.0,
        owasp_category="A02:2021-Cryptographic Failures",
        description=(
            "A broken or obsolete cryptographic primitive is in use. MD5 and SHA-1 "
            "have practical collision attacks; DES has a 56-bit key that is brute "
            "forceable. Neither is acceptable for passwords or integrity checks."
        ),
        suggested_fix=(
            "// For password storage, use a deliberately slow KDF:\n"
            "PasswordEncoder encoder = new BCryptPasswordEncoder(12);\n"
            "String hash = encoder.encode(rawPassword);\n"
            "\n"
            "// For general hashing:\n"
            "MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");"
        ),
        semantic_anchor="using a broken hash function such as MD5 or SHA-1 for security purposes",
    ),
    Signature(
        vulnerability_type="COMMAND_INJECTION",
        pattern=re.compile(
            r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\([^)]*\+", re.IGNORECASE
        ),
        severity=9.5,
        owasp_category="A03:2021-Injection",
        description=(
            "An OS command is built through string concatenation. If a concatenated "
            "value is attacker-controlled, shell metacharacters let them execute "
            "arbitrary commands with the privileges of the JVM process."
        ),
        suggested_fix=(
            "// Pass arguments as a list so no shell parsing occurs,\n"
            "// and validate the input against an allowlist first.\n"
            "ProcessBuilder pb = new ProcessBuilder(\"/usr/bin/convert\", inputPath, outputPath);\n"
            "pb.start();"
        ),
        semantic_anchor="executing an operating system command built from untrusted input",
    ),
    Signature(
        vulnerability_type="PATH_TRAVERSAL",
        pattern=re.compile(
            r"new\s+(File|FileInputStream|FileReader)\s*\([^)]*\+", re.IGNORECASE
        ),
        severity=7.5,
        owasp_category="A01:2021-Broken Access Control",
        description=(
            "A filesystem path is constructed from concatenated input. A value "
            "containing '../' lets an attacker read or write files outside the "
            "intended directory."
        ),
        suggested_fix=(
            "Path base = Paths.get(\"/var/app/uploads\").toAbsolutePath().normalize();\n"
            "Path target = base.resolve(userSuppliedName).normalize();\n"
            "if (!target.startsWith(base)) {\n"
            "    throw new SecurityException(\"Path traversal attempt blocked\");\n"
            "}"
        ),
        semantic_anchor="opening a file whose path is built from untrusted user input",
    ),
    Signature(
        vulnerability_type="EMPTY_CATCH_BLOCK",
        pattern=re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}"),
        severity=4.0,
        owasp_category="A09:2021-Security Logging and Monitoring Failures",
        description=(
            "An exception is caught and discarded without logging or handling. "
            "Real failures — including attacks in progress — become invisible."
        ),
        suggested_fix=(
            "catch (IOException ex) {\n"
            "    log.error(\"Failed to read configuration\", ex);\n"
            "    throw new ConfigurationException(\"Failed to read configuration\", ex);\n"
            "}"
        ),
        semantic_anchor="catching an exception and silently ignoring it without logging",
    ),
    Signature(
        vulnerability_type="RESOURCE_LEAK",
        pattern=re.compile(
            r"new\s+(FileInputStream|FileOutputStream|BufferedReader|Connection|Socket)\s*\("
        ),
        severity=5.0,
        owasp_category=None,
        description=(
            "A closeable resource is opened without a try-with-resources block. If an "
            "exception is thrown before close() runs, the file handle or socket leaks; "
            "under load this exhausts the descriptor limit."
        ),
        suggested_fix=(
            "try (BufferedReader reader = new BufferedReader(new FileReader(path))) {\n"
            "    return reader.lines().toList();\n"
            "}  // close() is called automatically, even on exception"
        ),
        semantic_anchor="opening a file or socket without closing it in a finally or try-with-resources block",
    ),
    Signature(
        vulnerability_type="STRING_CONCAT_IN_LOOP",
        # Inside a loop, find `x += ...` where the right-hand side contains a
        # string literal somewhere before the semicolon. Requiring the quote
        # immediately after `+=` would miss `result += row + ","`, while
        # allowing any RHS would wrongly flag numeric accumulators (`sum += v`).
        pattern=re.compile(
            r"for\s*\([^)]*\)\s*\{[^}]*?\w+\s*\+=\s*[^;]*[\"']", re.DOTALL
        ),
        severity=3.5,
        owasp_category=None,
        description=(
            "A String is built with += inside a loop. Strings are immutable, so each "
            "iteration allocates a new object and copies the old contents, making the "
            "loop quadratic in the length of the result."
        ),
        suggested_fix=(
            "StringBuilder sb = new StringBuilder();\n"
            "for (String item : items) {\n"
            "    sb.append(item).append(\", \");\n"
            "}\n"
            "String result = sb.toString();"
        ),
        semantic_anchor="concatenating strings repeatedly inside a loop instead of using a StringBuilder",
    ),
    Signature(
        vulnerability_type="NULL_POINTER_RISK",
        pattern=re.compile(r"\.get\(\s*\)\s*\.\w+\(|\bgetParameter\([^)]*\)\s*\.\w+\("),
        severity=4.5,
        owasp_category=None,
        description=(
            "A method result is dereferenced immediately without a null check. If the "
            "call can return null, this throws a NullPointerException at runtime."
        ),
        suggested_fix=(
            "String value = request.getParameter(\"id\");\n"
            "if (value == null || value.isBlank()) {\n"
            "    throw new IllegalArgumentException(\"Parameter 'id' is required\");\n"
            "}\n"
            "// or: Optional.ofNullable(value).map(String::trim).orElseThrow();"
        ),
        semantic_anchor="dereferencing the result of a method call that may return null",
    ),
]


# ---------------------------------------------------------------------------
# Model wrapper
# ---------------------------------------------------------------------------


class CodeAnalyzer:
    """Loads the Hugging Face model once and scores snippets against signatures.

    The transformer contributes a *confidence* signal: we embed the snippet and
    each matched signature's semantic anchor, then take cosine similarity. A
    regex match with high semantic agreement is reported with more confidence
    than one that looks like a coincidence.
    """

    def __init__(self, model_name: str = "microsoft/codebert-base", device: str = "cpu"):
        self.model_name = model_name
        self.device = device
        self.tokenizer = None
        self.model = None
        self._torch = None

    # -- lifecycle ---------------------------------------------------------

    def load(self) -> None:
        """Load tokenizer + model into memory. Called once at app startup.

        Import torch/transformers lazily so the service can still start (in
        rule-only mode) on a machine where the ML stack is not installed —
        useful when you are demoing from a laptop with no GPU and a slow network.
        """
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer

            self._torch = torch
            logger.info("Loading model '%s' onto %s ...", self.model_name, self.device)

            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModel.from_pretrained(self.model_name)
            self.model.to(self.device)
            self.model.eval()  # disable dropout; we are not training

            logger.info("Model loaded successfully.")
        except Exception as exc:  # noqa: BLE001 - we intentionally degrade
            logger.warning(
                "Could not load model '%s' (%s). Falling back to rule-only mode.",
                self.model_name,
                exc,
            )
            self.tokenizer = None
            self.model = None

    @property
    def is_loaded(self) -> bool:
        return self.model is not None and self.tokenizer is not None

    # -- embedding ---------------------------------------------------------

    def _embed(self, text: str):
        """Return a mean-pooled sentence embedding for `text`, or None."""
        if not self.is_loaded:
            return None

        torch = self._torch
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,  # CodeBERT's positional limit
            padding=True,
        ).to(self.device)

        with torch.no_grad():  # no gradients needed for inference
            outputs = self.model(**inputs)

        # Mean-pool the last hidden state over real (non-padding) tokens.
        hidden = outputs.last_hidden_state              # (1, seq_len, hidden)
        mask = inputs["attention_mask"].unsqueeze(-1)   # (1, seq_len, 1)
        summed = (hidden * mask).sum(dim=1)
        counts = mask.sum(dim=1).clamp(min=1e-9)
        return summed / counts

    def _similarity(self, code: str, anchor: str) -> float:
        """Cosine similarity between a snippet and a weakness description."""
        if not self.is_loaded:
            return 0.5  # neutral confidence in rule-only mode

        try:
            torch = self._torch
            code_vec = self._embed(code)
            anchor_vec = self._embed(anchor)
            if code_vec is None or anchor_vec is None:
                return 0.5

            sim = torch.nn.functional.cosine_similarity(code_vec, anchor_vec).item()
            # Cosine ranges [-1, 1]; map to [0, 1] for a confidence value.
            return max(0.0, min(1.0, (sim + 1.0) / 2.0))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Embedding failed, using neutral confidence: %s", exc)
            return 0.5

    # -- public inference API ---------------------------------------------

    def analyze(self, code: str, hint: Optional[str] = None) -> dict:
        """Analyze one snippet and return the highest-severity finding.

        Returns a dict matching the PredictResponse schema. When nothing is
        found, `vulnerability_type` is "NONE" — the Java side treats that as
        "this method is clean" and stores nothing.
        """
        matches: list[tuple[Signature, float]] = []

        for signature in SIGNATURES:
            if signature.pattern.search(code):
                confidence = self._similarity(code, signature.semantic_anchor)

                # The Java static pass already suspected this class of problem,
                # so treat agreement between the two as corroboration.
                if hint and self._hint_agrees(hint, signature.vulnerability_type):
                    confidence = min(1.0, confidence + 0.15)

                matches.append((signature, confidence))

        if not matches:
            return {
                "vulnerability_type": "NONE",
                "severity_score": 0.0,
                "issue_description": "No known vulnerability pattern detected in this snippet.",
                "suggested_fix": None,
                "owasp_category": None,
                "confidence": 0.0,
                "model_version": self.model_name if self.is_loaded else "rule-only",
            }

        # Report the most serious finding, breaking ties by model confidence.
        signature, confidence = max(matches, key=lambda m: (m[0].severity, m[1]))

        return {
            "vulnerability_type": signature.vulnerability_type,
            "severity_score": signature.severity,
            "issue_description": signature.description,
            "suggested_fix": signature.suggested_fix,
            "owasp_category": signature.owasp_category,
            "confidence": round(confidence, 3),
            "model_version": self.model_name if self.is_loaded else "rule-only",
        }

    @staticmethod
    def _hint_agrees(hint: str, vulnerability_type: str) -> bool:
        """Does a Java-side hint point at the same weakness class?"""
        normalized = hint.lower().replace("possible_", "")
        return any(part and part in vulnerability_type.lower() for part in normalized.split(","))


# ---------------------------------------------------------------------------
# Extension point for a fine-tuned classifier (roadmap week 4, optional)
# ---------------------------------------------------------------------------
#
# Swap AutoModel for AutoModelForSequenceClassification once you have a
# fine-tuned checkpoint, then replace CodeAnalyzer.analyze() with:
#
#   logits = self.model(**inputs).logits
#   probs = torch.softmax(logits, dim=-1)[0]
#   label_id = int(probs.argmax())
#   return {
#       "vulnerability_type": self.id2label[label_id],
#       "severity_score": float(probs[label_id]) * 10.0,
#       ...
#   }
#
# Datasets to fine-tune on: Devign, Big-Vul, or NIST's Juliet Java test suite.
