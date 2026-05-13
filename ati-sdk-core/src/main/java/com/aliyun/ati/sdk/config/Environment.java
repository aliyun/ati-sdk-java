package com.aliyun.ati.sdk.config;

public enum Environment {

    PRE("https://ati-pre.aliyuncs.com"),

    PROD("https://ati.aliyuncs.com");

    private final String baseUrl;

    Environment(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public static Environment fromBaseUrl(String baseUrl) {
        for (Environment env : values()) {
            if (env.baseUrl.equals(baseUrl)) {
                return env;
            }
        }
        throw new IllegalArgumentException("Unknown environment for URL: " + baseUrl);
    }
}
