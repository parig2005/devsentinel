package com.devsentinel.service;

import com.devsentinel.dto.CodeSnippet;
import com.devsentinel.model.VulnerabilityFinding;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * AST-based rule engine. Runs entirely inside the JVM with no network calls,
 * which is what keeps DevSentinel useful when the Python AI service is down.
 *
 * Every rule works on JavaParser AST nodes rather than raw text, so findings
 * carry accurate line numbers and enclosing method names.
 */
@Slf4j
@Component
public class StaticRuleEngine {

    // Variable names that suggest a credential. \w* on both sides so camelCase
    // names such as dbPassword and apiKeyValue match, not only exact words.
    private static final Pattern SECRET_NAME = Pattern.compile(
            "(?i)\\w*(password|passwd|pwd|secret|api_?key|token|credential)\\w*");

    // Values that are obviously placeholders rather than real secrets.
    private static final Pattern PLACEHOLDER_SECRET = Pattern.compile(
            "(?i)^(|null|none|todo|changeme|change_me|xxx+|\\*+|\\$\\{.*}|<.*>)$");

    private static final Pattern SQL_KEYWORD = Pattern.compile(
            "(?i).*\\b(select|insert\\s+into|update|delete\\s+from)\\b.*");

    private static final List<String> SQL_EXEC_METHODS = List.of(
            "executeQuery", "executeUpdate", "execute", "createQuery", "createNativeQuery");

    private static final List<String> WEAK_HASH_ALGOS = List.of("MD5", "SHA1", "SHA-1");

    private static final List<String> FILE_TYPES = List.of(
            "File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter");

    private static final List<String> CLOSEABLE_TYPES = List.of(
            "FileInputStream", "FileOutputStream", "BufferedReader", "BufferedWriter",
            "FileReader", "FileWriter", "Socket", "ServerSocket");

    /**
     * Runs every rule over the compilation unit.
     *
     * @param cu       parsed AST
     * @param fileName original file name, stored on each finding
     */
    public List<VulnerabilityFinding> analyse(CompilationUnit cu, String fileName) {
        List<VulnerabilityFinding> findings = new ArrayList<>();
        findings.addAll(detectSqlInjection(cu, fileName));
        findings.addAll(detectHardcodedSecrets(cu, fileName));
        findings.addAll(detectWeakCryptography(cu, fileName));
        findings.addAll(detectCommandInjection(cu, fileName));
        findings.addAll(detectPathTraversal(cu, fileName));
        findings.addAll(detectEmptyCatchBlocks(cu, fileName));
        findings.addAll(detectStringConcatInLoop(cu, fileName));
        findings.addAll(detectResourceLeaks(cu, fileName));
        log.debug("Static rule engine produced {} findings for {}", findings.size(), fileName);
        return findings;
    }

    /** Extracts one snippet per method body, for the AI service to score. */
    public List<CodeSnippet> extractMethodSnippets(CompilationUnit cu) {
        List<CodeSnippet> snippets = new ArrayList<>();

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodDeclaration method, Void arg) {
                super.visit(method, arg);

                // Abstract and interface methods have no body — nothing to analyse.
                if (method.getBody().isEmpty()) return;

                snippets.add(CodeSnippet.builder()
                        .className(enclosingClass(method))
                        .methodName(method.getNameAsString())
                        .sourceCode(method.toString())
                        .startLine(lineOf(method))
                        .endLine(method.getEnd().map(p -> p.line).orElse(lineOf(method)))
                        .staticAnalysisHint(buildHint(method.toString()))
                        .build());
            }
        }, null);

        return snippets;
    }

    // =======================================================================
    // Rule 1 — SQL injection via string concatenation
    // =======================================================================

    /**
     * Two shapes are flagged:
     *   a) stmt.executeQuery("SELECT ... '" + name + "'")   — concat inline
     *   b) String q = "SELECT ... " + name; stmt.executeQuery(q);
     *
     * Working on the AST rather than a regex is what avoids the classic bug
     * where a quote character inside the SQL text breaks the pattern.
     */
    private List<VulnerabilityFinding> detectSqlInjection(CompilationUnit cu, String fileName) {
        List<VulnerabilityFinding> findings = new ArrayList<>();

        // (a) concatenation passed directly to an exec method
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr call, Void arg) {
                super.visit(call, arg);
                if (!SQL_EXEC_METHODS.contains(call.getNameAsString())) return;

                boolean concatenatedSql = call.getArguments().stream()
                        .anyMatch(a -> isSqlConcatenation(a));
                if (!concatenatedSql) return;

                findings.add(build("SQL_INJECTION", fileName, enclosingMethod(call),
                        lineOf(call), call.toString(),
                        "A SQL statement is built by concatenating a string literal with a "
                        + "variable and passed to '" + call.getNameAsString() + "'. If any "
                        + "concatenated value originates from user input, an attacker can "
                        + "change the structure of the query — bypassing authentication, "
                        + "reading other users' rows, or destroying data.",
                        "PreparedStatement ps = connection.prepareStatement(\n"
                        + "        \"SELECT * FROM users WHERE username = ?\");\n"
                        + "ps.setString(1, username);\n"
                        + "try (ResultSet rs = ps.executeQuery()) {\n"
                        + "    // consume results\n"
                        + "}"));
            }
        }, null);

        // (b) a local variable holding concatenated SQL
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(VariableDeclarator declarator, Void arg) {
                super.visit(declarator, arg);

                Optional<Expression> init = declarator.getInitializer();
                if (init.isEmpty() || !isSqlConcatenation(init.get())) return;

                findings.add(build("SQL_INJECTION", fileName, enclosingMethod(declarator),
                        lineOf(declarator), declarator.toString(),
                        "The variable '" + declarator.getNameAsString() + "' holds a SQL "
                        + "statement assembled through string concatenation. Any untrusted "
                        + "value concatenated here can alter the meaning of the query when "
                        + "it is later executed.",
                        "// Build the statement with bind parameters instead:\n"
                        + "String sql = \"SELECT * FROM users WHERE name = ?\";\n"
                        + "PreparedStatement ps = connection.prepareStatement(sql);\n"
                        + "ps.setString(1, name);"));
            }
        }, null);

        return findings;
    }

    /** True when an expression is a '+' chain containing SQL keywords. */
    private boolean isSqlConcatenation(Expression expr) {
        if (!(expr instanceof BinaryExpr binary)) return false;
        if (binary.getOperator() != BinaryExpr.Operator.PLUS) return false;
        // toString() of the whole chain includes the literals; a quote inside the
        // SQL text is harmless here because we never try to match quote pairs.
        return SQL_KEYWORD.matcher(binary.toString()).matches();
    }

    // =======================================================================
    // Rule 2 — hardcoded secrets
    // =======================================================================

    /**
     * Flags a variable whose NAME suggests a credential and whose initializer is
     * a non-trivial string literal. Checking the declarator (not raw text) keeps
     * the false-positive rate low: an unrelated string elsewhere in the file is
     * never flagged just because the word "password" appears nearby.
     */
    private List<VulnerabilityFinding> detectHardcodedSecrets(CompilationUnit cu, String fileName) {
        List<VulnerabilityFinding> findings = new ArrayList<>();

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(VariableDeclarator declarator, Void arg) {
                super.visit(declarator, arg);

                String varName = declarator.getNameAsString();
                if (!SECRET_NAME.matcher(varName).matches()) return;

                declarator.getInitializer()
                        .filter(StringLiteralExpr.class::isInstance)
                        .map(StringLiteralExpr.class::cast)
                        .filter(lit -> lit.getValue().length() >= 4)
                        // Skip obvious placeholders and property references.
                        .filter(lit -> !PLACEHOLDER_SECRET.matcher(lit.getValue()).matches())
                        .ifPresent(lit -> findings.add(build(
                                "HARDCODED_SECRET", fileName, enclosingMethod(declarator),
                                lineOf(declarator), declarator.toString(),
                                "The variable '" + varName + "' stores a credential as a "
                                + "hardcoded string literal. It will live permanently in Git "
                                + "history and can be recovered from the compiled .class file "
                                + "with any decompiler. Rotating it later requires a rebuild.",
                                "// Read the value from the environment instead:\n"
                                + "private static final String " + varName
                                + " = System.getenv(\"" + toEnvName(varName) + "\");\n\n"
                                + "// Or, in Spring Boot, externalise it:\n"
                                + "@Value(\"${app." + varName.toLowerCase() + "}\")\n"
                                + "private String " + varName + ";")));
            }
        }, null);

        return findings;
    }

    // =======================================================================
    // Rule 3 — weak cryptography
    // =======================================================================

    private List<VulnerabilityFinding> detectWeakCryptography(CompilationUnit cu, String fileName) {
        List<VulnerabilityFinding> findings = new ArrayList<>();

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr call, Void arg) {
                super.visit(call, arg);
                if (!"getInstance".equals(call.getNameAsString())) return;

                String scope = call.getScope().map(Object::toString).orElse("");
                boolean cryptoScope = scope.contains("MessageDigest") || scope.contains("Cipher");
                if (!cryptoScope) return;

                Optional<String> algo = call.getArguments().stream()
                        .filter(StringLiteralExpr.class::isInstance)
                        .map(a -> ((StringLiteralExpr) a).getValue())
                        .findFirst();
                if (algo.isEmpty()) return;

                String value = algo.get().toUpperCase();
                boolean weak = WEAK_HASH_ALGOS.stream().anyMatch(value::startsWith)
                        || value.startsWith("DES");
                if (!weak) return;

                findings.add(build("WEAK_CRYPTOGRAPHY", fileName, enclosingMethod(call),
                        lineOf(call), call.toString(),
                        "The algorithm '" + algo.get() + "' is cryptographically broken. MD5 "
                        + "and SHA-1 have practical collision attacks, and DES has a 56-bit "
                        + "key that can be brute-forced. Neither is acceptable for password "
                        + "storage or integrity verification.",
                        "// Passwords need a deliberately slow, salted KDF:\n"
                        + "PasswordEncoder encoder = new BCryptPasswordEncoder(12);\n"
                        + "String hash = encoder.encode(rawPassword);\n\n"
                        + "// General-purpose hashing:\n"
                        + "MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");"));
            }
        }, null);

        return findings;
    }

    // =======================================================================
    // Rule 4 — OS command injection
    // =======================================================================

    private List<VulnerabilityFinding> detectCommandInjection(CompilationUnit cu, String fileName) {
        List<VulnerabilityFinding> findings = new ArrayList<>();

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr call, Void arg) {
                super.visit(call, arg);
                if (!"exec".equals(call.getNameAsString())) return;

                boolean concatenatedArg = call.getArguments().stream()
                        .anyMatch(a -> a instanceof BinaryExpr be
                                && be.getOperator() == BinaryExpr.Operator.PLUS);
                if (!concatenatedArg) return;

                findings.add(build("COMMAND_INJECTION", fileName, enclosingMethod(call),
                        lineOf(call), call.toString(),
                        "An operating-system command is assembled by string concatenation and "
                        + "executed. Shell metacharacters in an attacker-controlled value "
                        + "(such as ; or &&) allow arbitrary commands to run with the "
                        + "privileges of the JVM process.",
                        "// Pass arguments as separate list elements so no shell parsing\n"
                        + "// happens, and validate the input against an allowlist first.\n"
                        + "ProcessBuilder pb = new ProcessBuilder(\n"
                        + "        \"/usr/bin/convert\", inputPath, outputPath);\n"
                        + "pb.start();"));
            }
        }, null);

        // ProcessBuilder("cmd " + userInput)
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(ObjectCreationExpr creation, Void arg) {
                super.visit(creation, arg);
                if (!"ProcessBuilder".equals(creation.getType().getNameAsString())) return;

                boolean concatenatedArg = creation.getArguments().stream()
                        .anyMatch(a -> a instanceof BinaryExpr be
                                && be.getOperator() == BinaryExpr.Operator.PLUS);
                if (!concatenatedArg) return;

                findings.add(build("COMMAND_INJECTION", fileName, enclosingMethod(creation),
                        lineOf(creation), creation.toString(),
                        "A ProcessBuilder command is built by concatenating untrusted input "
                        + "into a single string, which reintroduces shell-style parsing risks.",
                        "ProcessBuilder pb = new ProcessBuilder(\"/usr/bin/tool\", safeArg);"));
            }
        }, null);

        return findings;
    }

    // =======================================================================
    // Rule 5 — path traversal
    // =======================================================================

    private List<VulnerabilityFinding> detectPathTraversal(CompilationUnit cu, String fileName) {
        List<VulnerabilityFinding> findings = new ArrayList<>();

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(ObjectCreationExpr creation, Void arg) {
                super.visit(creation, arg);

                String type = creation.getType().getNameAsString();
                if (!FILE_TYPES.contains(type)) return;

                boolean concatenatedPath = creation.getArguments().stream()
                        .anyMatch(a -> a instanceof BinaryExpr be
                                && be.getOperator() == BinaryExpr.Operator.PLUS);
                if (!concatenatedPath) return;

                findings.add(build("PATH_TRAVERSAL", fileName, enclosingMethod(creation),
                        lineOf(creation), creation.toString(),
                        "A filesystem path is built from concatenated input. A value "
                        + "containing '../' lets an attacker escape the intended directory "
                        + "and read or overwrite arbitrary files the process can access.",
                        "Path base = Paths.get(\"/var/app/uploads\").toAbsolutePath().normalize();\n"
                        + "Path target = base.resolve(userSuppliedName).normalize();\n"
                        + "if (!target.startsWith(base)) {\n"
                        + "    throw new SecurityException(\"Path traversal attempt blocked\");\n"
                        + "}"));
            }
        }, null);

        return findings;
    }

    // =======================================================================
    // Rule 6 — empty catch blocks
    // =======================================================================

    private List<VulnerabilityFinding> detectEmptyCatchBlocks(CompilationUnit cu, String fileName) {
        List<VulnerabilityFinding> findings = new ArrayList<>();

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(CatchClause catchClause, Void arg) {
                super.visit(catchClause, arg);
                if (!catchClause.getBody().getStatements().isEmpty()) return;

                String exceptionType = catchClause.getParameter().getTypeAsString();
                String paramName = catchClause.getParameter().getNameAsString();

                findings.add(build("EMPTY_CATCH_BLOCK", fileName, enclosingMethod(catchClause),
                        lineOf(catchClause), catchClause.toString(),
                        "This catch block discards '" + exceptionType + "' without logging or "
                        + "handling it. Real failures — including attacks in progress — become "
                        + "invisible, and the method silently continues in an unexpected state.",
                        "catch (" + exceptionType + " " + paramName + ") {\n"
                        + "    log.error(\"Operation failed\", " + paramName + ");\n"
                        + "    throw new ServiceException(\"Operation failed\", " + paramName + ");\n"
                        + "}"));
            }
        }, null);

        return findings;
    }

    // =======================================================================
    // Rule 7 — String concatenation inside a loop
    // =======================================================================

    private List<VulnerabilityFinding> detectStringConcatInLoop(CompilationUnit cu, String fileName) {
        List<VulnerabilityFinding> findings = new ArrayList<>();

        VoidVisitorAdapter<Void> visitor = new VoidVisitorAdapter<>() {
            @Override
            public void visit(com.github.javaparser.ast.expr.AssignExpr assign, Void arg) {
                super.visit(assign, arg);
                if (assign.getOperator() != com.github.javaparser.ast.expr.AssignExpr.Operator.PLUS) {
                    return;
                }

                boolean insideLoop = assign.findAncestor(com.github.javaparser.ast.stmt.ForStmt.class).isPresent()
                        || assign.findAncestor(com.github.javaparser.ast.stmt.ForEachStmt.class).isPresent()
                        || assign.findAncestor(com.github.javaparser.ast.stmt.WhileStmt.class).isPresent();
                if (!insideLoop) return;

                // Only flag String targets; numeric += is perfectly normal.
                boolean looksLikeString = assign.getValue() instanceof StringLiteralExpr
                        || assign.getValue().toString().contains("\"");
                if (!looksLikeString) return;

                findings.add(build("STRING_CONCAT_IN_LOOP", fileName, enclosingMethod(assign),
                        lineOf(assign), assign.toString(),
                        "A String is accumulated with += inside a loop. Strings are immutable, "
                        + "so every iteration allocates a new object and copies the previous "
                        + "contents, making the loop quadratic in the length of the result.",
                        "StringBuilder sb = new StringBuilder();\n"
                        + "for (String item : items) {\n"
                        + "    sb.append(item).append(\", \");\n"
                        + "}\n"
                        + "String result = sb.toString();"));
            }
        };
        cu.accept(visitor, null);

        return findings;
    }

    // =======================================================================
    // Rule 8 — closeable resource opened outside try-with-resources
    // =======================================================================

    private List<VulnerabilityFinding> detectResourceLeaks(CompilationUnit cu, String fileName) {
        List<VulnerabilityFinding> findings = new ArrayList<>();

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(ObjectCreationExpr creation, Void arg) {
                super.visit(creation, arg);

                String type = creation.getType().getNameAsString();
                if (!CLOSEABLE_TYPES.contains(type)) return;

                // Inside a try-with-resources header? Then it is handled correctly.
                boolean managed = creation
                        .findAncestor(com.github.javaparser.ast.stmt.TryStmt.class)
                        .map(tryStmt -> tryStmt.getResources().stream()
                                .anyMatch(r -> r.toString().contains(type)))
                        .orElse(false);
                if (managed) return;

                findings.add(build("RESOURCE_LEAK", fileName, enclosingMethod(creation),
                        lineOf(creation), creation.toString(),
                        "A " + type + " is opened without try-with-resources. If an exception "
                        + "is thrown before close() runs, the underlying file handle or socket "
                        + "leaks; under sustained load this exhausts the process descriptor limit.",
                        "try (" + type + " resource = new " + type + "(path)) {\n"
                        + "    // use the resource\n"
                        + "}  // close() runs automatically, even on exception"));
            }
        }, null);

        return findings;
    }

    // =======================================================================
    // Helpers
    // =======================================================================

    /** Builds a finding, pulling severity/OWASP/confidence from the shared catalog. */
    private VulnerabilityFinding build(String type, String fileName, String methodName,
                                       int line, String snippet,
                                       String description, String remediation) {
        VulnerabilityCatalog.Meta meta = VulnerabilityCatalog.lookup(type);
        return VulnerabilityFinding.builder()
                .vulnerabilityType(type)
                .displayName(meta.getDisplayName())
                .severity(meta.getSeverity())
                .category(meta.getCategory())
                .owaspCategory(meta.getOwaspCategory())
                .fileName(fileName)
                .methodName(methodName)
                .lineNumber(line)
                .codeSnippet(truncate(snippet, 1500))
                .description(description)
                .remediation(remediation)
                .confidence(meta.getRuleConfidence())
                .detectionSource("STATIC")
                .build();
    }

    private static String enclosingClass(com.github.javaparser.ast.Node node) {
        return node.findAncestor(ClassOrInterfaceDeclaration.class)
                .map(ClassOrInterfaceDeclaration::getNameAsString)
                .orElse("UnknownClass");
    }

    private static String enclosingMethod(com.github.javaparser.ast.Node node) {
        return node.findAncestor(MethodDeclaration.class)
                .map(MethodDeclaration::getNameAsString)
                .orElse("<field or initializer>");
    }

    private static int lineOf(com.github.javaparser.ast.Node node) {
        return node.getBegin().map(p -> p.line).orElse(0);
    }

    private static String truncate(String text, int max) {
        if (text == null) return null;
        return text.length() <= max ? text : text.substring(0, max) + "\n// ... truncated";
    }

    /** dbPassword -> DB_PASSWORD */
    private static String toEnvName(String varName) {
        return varName.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toUpperCase();
    }

    /** Cheap textual hints passed to the AI service alongside the snippet. */
    private static String buildHint(String methodSource) {
        List<String> hints = new ArrayList<>();
        if (SQL_KEYWORD.matcher(methodSource).matches() && methodSource.contains("+")) {
            hints.add("possible_sql_injection");
        }
        if (SECRET_NAME.matcher(methodSource).find() && methodSource.contains("\"")) {
            hints.add("possible_hardcoded_secret");
        }
        if (methodSource.contains("catch") && methodSource.replaceAll("\\s", "").contains("){}")) {
            hints.add("possible_swallowed_exception");
        }
        return hints.isEmpty() ? null : String.join(",", hints);
    }
}
