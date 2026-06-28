package com.hour.authserver.dto.response;

public record ErrorResponse(
        int status,
        String error,
        String message,
        long timestamp
) {
    public static ErrorResponse of(int status, String error, String message) {
        return new ErrorResponse(status, error, message, System.currentTimeMillis());
    }
}