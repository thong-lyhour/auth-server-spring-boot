package com.hour.authserver.controller;

import com.hour.authserver.dto.request.LoginRequest;
import com.hour.authserver.dto.request.RefreshRequest;
import com.hour.authserver.dto.request.RegisterRequest;
import com.hour.authserver.dto.response.RefreshResponse;
import com.hour.authserver.dto.response.TokenResponse;
import com.hour.authserver.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /auth/login
     * Body: { "username": "alice", "password": "secret" }
     * Returns: access token + refresh token
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * POST /auth/refresh
     * Body: { "refreshToken": "<uuid>" }
     * Returns: new access token + new refresh token (old one is revoked)
     */
    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    /**
     * POST /auth/logout
     * Body: { "refreshToken": "<uuid>" }
     * Revokes the refresh token in Redis.
     * The access token expires naturally (short TTL).
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody RefreshRequest request) {
        authService.logout(request.refreshToken());
        return ResponseEntity.noContent().build();
    }

    /**
     * POST /auth/register  (demo — protect or remove in production)
     */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
