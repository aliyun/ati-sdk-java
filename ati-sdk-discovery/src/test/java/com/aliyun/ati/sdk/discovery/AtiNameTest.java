package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiNameTest {

    @Test
    void shouldParseValidAtiName() {
        AtiName name = AtiName.parse("ati://v1.my-agent.example.com");

        assertThat(name.getVersion()).isEqualTo("1");
        assertThat(name.getAgentHost()).isEqualTo("my-agent.example.com");
    }

    @Test
    void shouldParseSemanticVersion() {
        AtiName name = AtiName.parse("ati://v1.2.3.agent.example.com");

        assertThat(name.getVersion()).isEqualTo("1.2.3");
        assertThat(name.getAgentHost()).isEqualTo("agent.example.com");
    }

    @Test
    void shouldReturnOriginalUri() {
        String uri = "ati://v1.my-agent.example.com";
        AtiName name = AtiName.parse(uri);

        assertThat(name.toUri()).isEqualTo(uri);
    }

    @Test
    void shouldRejectNullInput() {
        assertThatThrownBy(() -> AtiName.parse(null))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldRejectInvalidScheme() {
        assertThatThrownBy(() -> AtiName.parse("http://v1.example.com"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("ati://");
    }

    @Test
    void shouldRejectMissingVersion() {
        assertThatThrownBy(() -> AtiName.parse("ati://example.com"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldImplementEqualsAndHashCode() {
        AtiName a = AtiName.parse("ati://v1.agent.example.com");
        AtiName b = AtiName.parse("ati://v1.agent.example.com");

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }
}
