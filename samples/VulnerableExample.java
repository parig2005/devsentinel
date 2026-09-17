package com.example.demo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

/**
 * Deliberately vulnerable demo class for DevSentinel AI.
 * Upload this during your viva — it triggers every detection rule.
 * DO NOT use any of this code in a real application.
 */
public class VulnerableExample {

    // Rule: HARDCODED_SECRET
    private static final String dbPassword = "SuperSecret123!";
    private String apiKey = "sk_live_51H8xQ2eZvKYlo2C";

    // Rule: SQL_INJECTION
    public ResultSet findUserByName(String username) throws SQLException {
        Connection conn = DriverManager.getConnection(
                "jdbc:postgresql://localhost:5432/app", "admin", dbPassword);
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
    }

    // Rule: WEAK_CRYPTOGRAPHY
    public String hashPassword(String raw) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return new String(digest.digest(raw.getBytes()));
    }

    // Rule: COMMAND_INJECTION
    public void generateThumbnail(String fileName) throws IOException {
        Runtime.getRuntime().exec("convert -resize 100x100 " + fileName);
    }

    // Rule: EMPTY_CATCH_BLOCK + RESOURCE_LEAK
    public String readConfig(String path) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(path));
            return reader.readLine();
        } catch (IOException e) {
        }
        return null;
    }

    // Rule: PATH_TRAVERSAL
    public String readUserFile(String fileName) throws IOException {
        File target = new File("/var/app/uploads/" + fileName);
        BufferedReader reader = new BufferedReader(new FileReader(target));
        return reader.readLine();
    }

    // Rule: STRING_CONCAT_IN_LOOP
    public String buildCsv(List<String> rows) {
        String result = "";
        for (String row : rows) {
            result += row + ",";
        }
        return result;
    }

    // Clean method — should produce no findings.
    public int calculateTotal(int quantity, int unitPrice) {
        return quantity * unitPrice;
    }
}
