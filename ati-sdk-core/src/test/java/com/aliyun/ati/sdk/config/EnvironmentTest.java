package com.aliyun.ati.sdk.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EnvironmentTest {

    @Test
    void shouldReturnCorrectBaseUrls() {
        assertThat(Environment.PRE.getBaseUrl())
            .isEqualTo("https://ati-pre.aliyuncs.com");
        assertThat(Environment.PROD.getBaseUrl())
            .isEqualTo("https://ati.aliyuncs.com");
    }

    @Test
    void shouldLookupByBaseUrl() {
        assertThat(Environment.fromBaseUrl("https://ati-pre.aliyuncs.com"))
            .isEqualTo(Environment.PRE);
        assertThat(Environment.fromBaseUrl("https://ati.aliyuncs.com"))
            .isEqualTo(Environment.PROD);
    }

    @Test
    void shouldThrowForUnknownBaseUrl() {
        assertThatThrownBy(() -> Environment.fromBaseUrl("https://unknown.com"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unknown environment");
    }
}
