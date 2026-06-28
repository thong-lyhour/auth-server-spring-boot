package com.hour.authserver.dto.response;

public record RefreshResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn
) {}