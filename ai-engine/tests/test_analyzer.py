"""Detection-rule tests for the DevSentinel analyzer.

Run with:  pytest tests/ -v

These run in rule-only mode (no model load), so they are fast and need no
network. That matters: you want a test suite you can run in front of an
examiner without waiting on a 500 MB download.
"""

import pytest

from app.analyzer import CodeAnalyzer


@pytest.fixture(scope="module")
def analyzer() -> CodeAnalyzer:
    # Intentionally not calling .load() — rule layer only.
    return CodeAnalyzer()


SQL_INJECTION_SNIPPET = """
public User findUser(String name) throws SQLException {
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    return map(rs);
}
"""

HARDCODED_SECRET_SNIPPET = """
public void connect() {
    String dbPassword = "SuperSecret123";
    DriverManager.getConnection(url, "admin", dbPassword);
}
"""

WEAK_CRYPTO_SNIPPET = """
public String hash(String input) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    return new String(md.digest(input.getBytes()));
}
"""

COMMAND_INJECTION_SNIPPET = """
public void convert(String file) throws IOException {
    Runtime.getRuntime().exec("convert " + file);
}
"""

EMPTY_CATCH_SNIPPET = """
public void load() {
    try { readConfig(); } catch (IOException e) {}
}
"""

STRING_CONCAT_LOOP_SNIPPET = """
public String join(List<String> items) {
    String out = "";
    for (String s : items) { out += ", "; }
    return out;
}
"""

CLEAN_SNIPPET = """
public int add(int a, int b) {
    return a + b;
}
"""


@pytest.mark.parametrize(
    "snippet,expected_type",
    [
        (SQL_INJECTION_SNIPPET, "SQL_INJECTION"),
        (HARDCODED_SECRET_SNIPPET, "HARDCODED_SECRET"),
        (WEAK_CRYPTO_SNIPPET, "WEAK_CRYPTOGRAPHY"),
        (COMMAND_INJECTION_SNIPPET, "COMMAND_INJECTION"),
        (EMPTY_CATCH_SNIPPET, "EMPTY_CATCH_BLOCK"),
        (STRING_CONCAT_LOOP_SNIPPET, "STRING_CONCAT_IN_LOOP"),
        (CLEAN_SNIPPET, "NONE"),
    ],
)
def test_detects_expected_vulnerability(analyzer, snippet, expected_type):
    result = analyzer.analyze(snippet)
    assert result["vulnerability_type"] == expected_type


def test_clean_code_has_zero_severity(analyzer):
    result = analyzer.analyze(CLEAN_SNIPPET)
    assert result["severity_score"] == 0.0
    assert result["suggested_fix"] is None


def test_finding_includes_remediation(analyzer):
    result = analyzer.analyze(SQL_INJECTION_SNIPPET)
    assert result["suggested_fix"]
    assert "PreparedStatement" in result["suggested_fix"]
    assert result["owasp_category"] == "A03:2021-Injection"


def test_severity_scores_are_in_range(analyzer):
    for snippet in (SQL_INJECTION_SNIPPET, WEAK_CRYPTO_SNIPPET, EMPTY_CATCH_SNIPPET):
        score = analyzer.analyze(snippet)["severity_score"]
        assert 0.0 <= score <= 10.0


def test_most_severe_finding_wins(analyzer):
    """A snippet with both a critical and a minor issue reports the critical one."""
    combined = """
    public void doIt(String name) throws Exception {
        String apiKey = "abc123secret";
        Runtime.getRuntime().exec("ls " + name);
    }
    """
    result = analyzer.analyze(combined)
    # COMMAND_INJECTION (9.5) outranks HARDCODED_SECRET (7.5)
    assert result["vulnerability_type"] == "COMMAND_INJECTION"


def test_matching_hint_raises_confidence(analyzer):
    without = analyzer.analyze(SQL_INJECTION_SNIPPET)
    with_hint = analyzer.analyze(SQL_INJECTION_SNIPPET, hint="possible_sql_injection")
    assert with_hint["confidence"] >= without["confidence"]


# ---------------------------------------------------------------------------
# Regression tests for rules fixed after real-file testing
# ---------------------------------------------------------------------------


CONCAT_WITH_VARIABLE_SNIPPET = """
public String buildCsv(List<String> rows) {
    String result = "";
    for (String row : rows) {
        result += row + ",";
    }
    return result;
}
"""

NUMERIC_ACCUMULATOR_SNIPPET = """
public int total(int[] values) {
    int sum = 0;
    for (int v : values) {
        sum += v;
    }
    return sum;
}
"""


def test_detects_concat_in_loop_with_variable_rhs(analyzer):
    """`result += row + ","` must be caught, not just `out += ", "`."""
    result = analyzer.analyze(CONCAT_WITH_VARIABLE_SNIPPET)
    assert result["vulnerability_type"] == "STRING_CONCAT_IN_LOOP"


def test_numeric_accumulation_in_loop_is_not_flagged(analyzer):
    """Guards against the obvious over-correction of the rule above."""
    result = analyzer.analyze(NUMERIC_ACCUMULATOR_SNIPPET)
    assert result["vulnerability_type"] != "STRING_CONCAT_IN_LOOP"


def test_sql_injection_with_quotes_inside_string(analyzer):
    """Regression: a quote inside the SQL text must not break detection."""
    snippet = """
    public void find(String name) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name='" + name + "'");
    }
    """
    assert analyzer.analyze(snippet)["vulnerability_type"] == "SQL_INJECTION"


def test_camel_case_secret_is_detected(analyzer):
    """Regression: dbPassword / apiKey style names must match."""
    for snippet in (
        'public void c() { String dbPassword = "secret123"; }',
        'public void c() { String apiKey = "abc123xyz"; }',
    ):
        assert analyzer.analyze(snippet)["vulnerability_type"] == "HARDCODED_SECRET"
