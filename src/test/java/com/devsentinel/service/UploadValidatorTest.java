package com.devsentinel.service;

import com.devsentinel.exception.InvalidUploadException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UploadValidatorTest {

    private UploadValidator validator;

    @BeforeEach
    void setUp() {
        validator = new UploadValidator("1MB");
    }

    private MockMultipartFile file(String name, String content) {
        return new MockMultipartFile("file", name, "text/plain",
                content.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("accepts a well-formed .java upload")
    void acceptsValidJavaFile() {
        assertThatCode(() -> validator.validate(file("Foo.java", "public class Foo {}")))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("rejects a non-Java extension")
    void rejectsNonJavaExtension() {
        assertThatThrownBy(() -> validator.validate(file("notes.txt", "hello")))
                .isInstanceOf(InvalidUploadException.class)
                .hasMessageContaining(".java");
    }

    @Test
    @DisplayName("rejects an empty upload")
    void rejectsEmptyFile() {
        assertThatThrownBy(() -> validator.validate(file("Foo.java", "")))
                .isInstanceOf(InvalidUploadException.class);
    }

    @Test
    @DisplayName("rejects path traversal in the file name")
    void rejectsPathTraversal() {
        assertThatThrownBy(() -> validator.validate(file("../../etc/passwd.java", "public class A {}")))
                .isInstanceOf(InvalidUploadException.class)
                .hasMessageContaining("invalid path characters");
    }

    @Test
    @DisplayName("rejects a file larger than the configured limit")
    void rejectsOversizedFile() {
        UploadValidator small = new UploadValidator("10B");
        assertThatThrownBy(() -> small.validate(file("Foo.java", "public class Foo { int x; }")))
                .isInstanceOf(InvalidUploadException.class)
                .hasMessageContaining("too large");
    }

    @Test
    @DisplayName("rejects binary content disguised as .java")
    void rejectsBinaryContent() {
        byte[] binary = new byte[]{0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00};
        assertThatThrownBy(() -> validator.validateContent(binary, "Foo.java"))
                .isInstanceOf(InvalidUploadException.class)
                .hasMessageContaining("binary");
    }

    @Test
    @DisplayName("rejects text with no Java type declaration")
    void rejectsNonJavaContent() {
        byte[] plain = "just some prose, not code at all".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> validator.validateContent(plain, "Foo.java"))
                .isInstanceOf(InvalidUploadException.class)
                .hasMessageContaining("Java type declaration");
    }

    @Test
    @DisplayName("accepts valid Java content")
    void acceptsValidContent() {
        byte[] java = "public class Foo { }".getBytes(StandardCharsets.UTF_8);
        assertThatCode(() -> validator.validateContent(java, "Foo.java"))
                .doesNotThrowAnyException();
    }
}
