package com.devsentinel.service;

import com.devsentinel.dto.CodeSnippet;
import com.devsentinel.model.VulnerabilityFinding;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Rule-engine tests. These mirror the Python suite in ai-engine/tests so both
 * halves of the system are held to the same detection expectations.
 */
class StaticRuleEngineTest {

    private StaticRuleEngine engine;

    @BeforeEach
    void setUp() {
        engine = new StaticRuleEngine();
    }

    private List<VulnerabilityFinding> analyse(String source) {
        JavaParser parser = new JavaParser(
                new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17));
        CompilationUnit cu = parser.parse(source).getResult().orElseThrow();
        return engine.analyse(cu, "Test.java");
    }

    private boolean hasType(List<VulnerabilityFinding> findings, String type) {
        return findings.stream().anyMatch(f -> f.getVulnerabilityType().equals(type));
    }

    // -----------------------------------------------------------------------
    // SQL injection — including the quote-inside-the-string case
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("detects SQL injection when the query contains single quotes")
    void detectsSqlInjectionWithQuotesInsideString() {
        // This is the exact shape that broke an earlier regex-based detector.
        String source = """
                public class UserDao {
                    public void find(String name) throws Exception {
                        Statement stmt = conn.createStatement();
                        stmt.executeQuery("SELECT * FROM users WHERE name='" + name + "'");
                    }
                }
                """;
        assertThat(hasType(analyse(source), "SQL_INJECTION")).isTrue();
    }

    @Test
    @DisplayName("detects SQL injection assigned to a local variable first")
    void detectsSqlInjectionViaVariable() {
        String source = """
                public class UserDao {
                    public void find(String name) throws Exception {
                        String query = "SELECT * FROM users WHERE name='" + name + "'";
                        stmt.executeQuery(query);
                    }
                }
                """;
        assertThat(hasType(analyse(source), "SQL_INJECTION")).isTrue();
    }

    @Test
    @DisplayName("does not flag a parameterised query as injection")
    void ignoresPreparedStatement() {
        String source = """
                public class UserDao {
                    public void find(String name) throws Exception {
                        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
                        ps.setString(1, name);
                        ps.executeQuery();
                    }
                }
                """;
        assertThat(hasType(analyse(source), "SQL_INJECTION")).isFalse();
    }

    // -----------------------------------------------------------------------
    // Hardcoded secrets — including camelCase names
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("detects a camelCase hardcoded secret such as dbPassword")
    void detectsCamelCaseSecret() {
        String source = """
                public class Config {
                    public void connect() {
                        String dbPassword = "secret123";
                        System.out.println(dbPassword);
                    }
                }
                """;
        assertThat(hasType(analyse(source), "HARDCODED_SECRET")).isTrue();
    }

    @Test
    @DisplayName("detects an apiKey field")
    void detectsApiKeyField() {
        String source = """
                public class Config {
                    private String apiKey = "abc123xyz";
                }
                """;
        assertThat(hasType(analyse(source), "HARDCODED_SECRET")).isTrue();
    }

    @Test
    @DisplayName("does not flag a secret loaded from the environment")
    void ignoresEnvironmentSecret() {
        String source = """
                public class Config {
                    private String dbPassword = System.getenv("DB_PASSWORD");
                }
                """;
        assertThat(hasType(analyse(source), "HARDCODED_SECRET")).isFalse();
    }

    @Test
    @DisplayName("does not flag placeholder values")
    void ignoresPlaceholderSecret() {
        String source = """
                public class Config {
                    private String dbPassword = "changeme";
                }
                """;
        assertThat(hasType(analyse(source), "HARDCODED_SECRET")).isFalse();
    }

    @Test
    @DisplayName("does not flag an unrelated variable holding a string")
    void ignoresUnrelatedVariable() {
        String source = """
                public class Greeter {
                    private String greeting = "hello world";
                }
                """;
        assertThat(hasType(analyse(source), "HARDCODED_SECRET")).isFalse();
    }

    // -----------------------------------------------------------------------
    // Remaining rules
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("detects MD5 as weak cryptography")
    void detectsWeakCrypto() {
        String source = """
                public class Hasher {
                    public void hash() throws Exception {
                        MessageDigest md = MessageDigest.getInstance("MD5");
                    }
                }
                """;
        assertThat(hasType(analyse(source), "WEAK_CRYPTOGRAPHY")).isTrue();
    }

    @Test
    @DisplayName("accepts SHA-256 without flagging it")
    void ignoresStrongCrypto() {
        String source = """
                public class Hasher {
                    public void hash() throws Exception {
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                    }
                }
                """;
        assertThat(hasType(analyse(source), "WEAK_CRYPTOGRAPHY")).isFalse();
    }

    @Test
    @DisplayName("detects command injection through Runtime.exec")
    void detectsCommandInjection() {
        String source = """
                public class Runner {
                    public void run(String f) throws Exception {
                        Runtime.getRuntime().exec("convert " + f);
                    }
                }
                """;
        assertThat(hasType(analyse(source), "COMMAND_INJECTION")).isTrue();
    }

    @Test
    @DisplayName("detects path traversal in a concatenated File path")
    void detectsPathTraversal() {
        String source = """
                public class Loader {
                    public void load(String name) throws Exception {
                        File f = new File("/uploads/" + name);
                    }
                }
                """;
        assertThat(hasType(analyse(source), "PATH_TRAVERSAL")).isTrue();
    }

    @Test
    @DisplayName("detects an empty catch block")
    void detectsEmptyCatch() {
        String source = """
                public class Loader {
                    public void load() {
                        try { read(); } catch (Exception e) {}
                    }
                }
                """;
        assertThat(hasType(analyse(source), "EMPTY_CATCH_BLOCK")).isTrue();
    }

    @Test
    @DisplayName("does not flag a catch block that logs")
    void ignoresHandledCatch() {
        String source = """
                public class Loader {
                    public void load() {
                        try { read(); } catch (Exception e) { log.error("failed", e); }
                    }
                }
                """;
        assertThat(hasType(analyse(source), "EMPTY_CATCH_BLOCK")).isFalse();
    }

    @Test
    @DisplayName("detects String += inside a loop")
    void detectsStringConcatInLoop() {
        String source = """
                public class Joiner {
                    public String join(List<String> items) {
                        String out = "";
                        for (String s : items) { out += ", "; }
                        return out;
                    }
                }
                """;
        assertThat(hasType(analyse(source), "STRING_CONCAT_IN_LOOP")).isTrue();
    }

    @Test
    @DisplayName("does not flag numeric += inside a loop")
    void ignoresNumericAccumulationInLoop() {
        String source = """
                public class Summer {
                    public int total(int[] values) {
                        int sum = 0;
                        for (int v : values) { sum += v; }
                        return sum;
                    }
                }
                """;
        assertThat(hasType(analyse(source), "STRING_CONCAT_IN_LOOP")).isFalse();
    }

    @Test
    @DisplayName("does not flag a resource opened with try-with-resources")
    void ignoresManagedResource() {
        String source = """
                public class Reader1 {
                    public void read(String p) throws Exception {
                        try (BufferedReader r = new BufferedReader(new FileReader(p))) {
                            r.readLine();
                        }
                    }
                }
                """;
        assertThat(hasType(analyse(source), "RESOURCE_LEAK")).isFalse();
    }

    // -----------------------------------------------------------------------
    // Finding quality + snippet extraction
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("clean code produces no findings")
    void cleanCodeProducesNoFindings() {
        String source = """
                public class Calculator {
                    public int add(int a, int b) { return a + b; }
                }
                """;
        assertThat(analyse(source)).isEmpty();
    }

    @Test
    @DisplayName("every finding carries the metadata the UI renders")
    void findingsCarryCompleteMetadata() {
        String source = """
                public class UserDao {
                    public void find(String name) throws Exception {
                        stmt.executeQuery("SELECT * FROM users WHERE name='" + name + "'");
                    }
                }
                """;
        List<VulnerabilityFinding> findings = analyse(source);
        assertThat(findings).isNotEmpty();

        VulnerabilityFinding f = findings.get(0);
        assertThat(f.getVulnerabilityType()).isNotBlank();
        assertThat(f.getDisplayName()).isNotBlank();
        assertThat(f.getSeverity()).isIn("CRITICAL", "HIGH", "MEDIUM", "LOW");
        assertThat(f.getCategory()).isNotBlank();
        assertThat(f.getFileName()).isEqualTo("Test.java");
        assertThat(f.getMethodName()).isEqualTo("find");
        assertThat(f.getLineNumber()).isGreaterThan(0);
        assertThat(f.getDescription()).isNotBlank();
        assertThat(f.getRemediation()).isNotBlank();
        assertThat(f.getConfidence()).isBetween(0.0, 1.0);
        assertThat(f.getDetectionSource()).isEqualTo("STATIC");
    }

    @Test
    @DisplayName("extracts one snippet per method with a body")
    void extractsMethodSnippets() {
        String source = """
                public class Sample {
                    public void one() { int x = 1; }
                    public void two() { int y = 2; }
                }
                """;
        JavaParser parser = new JavaParser(
                new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17));
        CompilationUnit cu = parser.parse(source).getResult().orElseThrow();

        List<CodeSnippet> snippets = engine.extractMethodSnippets(cu);
        assertThat(snippets).hasSize(2);
        assertThat(snippets).extracting(CodeSnippet::getMethodName)
                .containsExactlyInAnyOrder("one", "two");
        assertThat(snippets.get(0).getClassName()).isEqualTo("Sample");
        assertThat(snippets.get(0).getStartLine()).isGreaterThan(0);
    }
}
