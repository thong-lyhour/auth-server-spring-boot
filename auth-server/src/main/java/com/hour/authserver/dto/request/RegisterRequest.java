package com.hour.authserver.dto.request;

import jakarta.validation.constraints.NotBlank;

public record RegisterRequest(
        @NotBlank String username,
        @NotBlank String email,
        @NotBlank String password,
        @NotBlank String role
) {}
