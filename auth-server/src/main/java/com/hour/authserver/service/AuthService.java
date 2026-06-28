package com.hour.authserver.service;

import com.hour.authserver.configuration.property.RsaKeyProperties;
import com.hour.authserver.dto.request.LoginRequest;
import com.hour.authserver.dto.request.RefreshRequest;
import com.hour.authserver.dto.request.RegisterRequest;
import com.hour.authserver.dto.response.RefreshResponse;
import com.hour.authserver.dto.response.TokenResponse;
import com.hour.authserver.entity.User;
import com.hour.authserver.exception.InvalidTokenException;
import com.hour.authserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final RsaKeyProperties rsaKeys;

    // ── Login ─────────────────────────────────────────────────────────────────

    public TokenResponse login(LoginRequest request) {
        // Throws BadCredentialsException if invalid — handled globally
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.username());

        String accessToken  = tokenService.issueAccessToken(userDetails);
        String refreshToken = tokenService.issueRefreshToken(userDetails.getUsername());

        log.info("User logged in: {}", request.username());

        return new TokenResponse(
                accessToken,
                refreshToken,
                "Bearer",
                rsaKeys.accessTokenExpiry()
        );
    }

    // ── Refresh ───────────────────────────────────────────────────────────────

    public RefreshResponse refresh(RefreshRequest request) {
        // First validate the incoming refresh token
        String username = tokenService.validateRefreshToken(request.refreshToken());

        // Load user to get fresh roles (in case they changed)
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Issue new access token
        String newAccessToken  = tokenService.issueAccessToken(userDetails);

        // Rotate refresh token (invalidate old, issue new)
        String newRefreshToken = tokenService.issueRefreshToken(username);
        tokenService.revokeRefreshToken(request.refreshToken()); // revoke old

        log.info("Token refreshed for user: {}", username);

        return new RefreshResponse(
                newAccessToken,
                newRefreshToken,
                "Bearer",
                rsaKeys.accessTokenExpiry()
        );
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    public void logout(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new InvalidTokenException("Refresh token is required for logout");
        }
        tokenService.revokeRefreshToken(refreshToken);
        log.info("User logged out, refresh token revoked");
    }

    // ── Register (demo use) ───────────────────────────────────────────────────

    public void register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new IllegalArgumentException("Username already taken");
        }
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already registered");
        }

        User user = User.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(request.role())
                .enabled(true)
                .build();

        userRepository.save(user);
        log.info("Registered new user: {}", request.username());
    }
}
