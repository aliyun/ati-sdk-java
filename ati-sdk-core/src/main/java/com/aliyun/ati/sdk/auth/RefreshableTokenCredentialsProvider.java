package com.aliyun.ati.sdk.auth;

import com.aliyun.ati.sdk.exception.AtiAuthenticationException;

import java.util.function.Supplier;

public final class RefreshableTokenCredentialsProvider implements AtiCredentialsProvider {

    private final Supplier<String> tokenSupplier;

    public RefreshableTokenCredentialsProvider(Supplier<String> tokenSupplier) {
        if (tokenSupplier == null) {
            throw new IllegalArgumentException("Token supplier cannot be null");
        }
        this.tokenSupplier = tokenSupplier;
    }

    @Override
    public AtiCredentials resolveCredentials() {
        try {
            String token = tokenSupplier.get();
            if (token == null || token.isBlank()) {
                throw new AtiAuthenticationException(
                    "Token supplier returned null or blank token");
            }
            return AtiCredentials.ofAccessToken(token);
        } catch (AtiAuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new AtiAuthenticationException(
                "Failed to obtain access token: " + e.getMessage(), e);
        }
    }
}
