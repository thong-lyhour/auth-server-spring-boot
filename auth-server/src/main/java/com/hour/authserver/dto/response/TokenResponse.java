package com.hour.authserver.dto.response;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        long expiresIn   // access token TTL in seconds
) {}