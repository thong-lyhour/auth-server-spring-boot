package com.hour.authserver.service;

import com.hour.authserver.configuration.property.RsaKeyProperties;
import com.hour.authserver.exception.InvalidTokenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private static final String REFRESH_KEY_PREFIX = "refresh:";

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final StringRedisTemplate redisTemplate;
    private final RsaKeyProperties rsaKeys;

    // ── Access Token ──────────────────────────────────────────────────────────

    public String issueAccessToken(UserDetails userDetails) {
        Instant now = Instant.now();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(rsaKeys.issuer())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(rsaKeys.accessTokenExpiry()))
                .subject(userDetails.getUsername())
                .id(UUID.randomUUID().toString())   // jti
                .claim("roles", roles)
                .claim("type", "access")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    // ── Refresh Token ─────────────────────────────────────────────────────────

    /**
     * Issues a refresh token and stores its jti in Redis.
     * The token value itself is an opaque UUID — NOT a JWT.
     * This avoids stateless refresh tokens which can't be revoked.
     */
    public String issueRefreshToken(String username) {
        String jti = UUID.randomUUID().toString();
        String redisKey = REFRESH_KEY_PREFIX + jti;

        redisTemplate.opsForValue().set(
                redisKey,
                username,
                rsaKeys.refreshTokenExpiry(),
                TimeUnit.SECONDS
        );

        log.debug("Issued refresh token for user: {}", username);
        return jti; // the token value is just the UUID
    }

    /**
     * Validates a refresh token, rotates it (deletes old, issues new),
     * and returns the username it belongs to.
     */
    public String rotateRefreshToken(String refreshToken, String newRefreshToken) {
        String redisKey = REFRESH_KEY_PREFIX + refreshToken;
        String username = redisTemplate.opsForValue().get(redisKey);

        if (username == null) {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }

        // Rotate: delete old token (one-time use), store new one
        redisTemplate.delete(redisKey);
        redisTemplate.opsForValue().set(
                REFRESH_KEY_PREFIX + newRefreshToken,
                username,
                rsaKeys.refreshTokenExpiry(),
                TimeUnit.SECONDS
        );

        return username;
    }

    /**
     * Validates refresh token and returns the associated username without rotating.
     * Used internally to verify before generating new access token.
     */
    public String validateRefreshToken(String refreshToken) {
        String redisKey = REFRESH_KEY_PREFIX + refreshToken;
        String username = redisTemplate.opsForValue().get(redisKey);

        if (username == null) {
            throw new InvalidTokenException("Refresh token is invalid or expired");
        }
        return username;
    }

    /**
     * Revokes a refresh token on logout.
     */
    public void revokeRefreshToken(String refreshToken) {
        String redisKey = REFRESH_KEY_PREFIX + refreshToken;
        Boolean deleted = redisTemplate.delete(redisKey);
        if (Boolean.TRUE.equals(deleted)) {
            log.debug("Revoked refresh token: {}", refreshToken);
        }
    }

    /**
     * Decodes and validates an access token (used by other services, exposed here for the JWKS flow).
     */
    public Jwt decodeAccessToken(String token) {
        try {
            return jwtDecoder.decode(token);
        } catch (JwtException e) {
            throw new InvalidTokenException("Access token is invalid: " + e.getMessage());
        }
    }
}
