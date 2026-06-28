package com.hour.authserver.controller;

import com.hour.authserver.configuration.security.SecurityConfig;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Serves the JSON Web Key Set (JWKS) so downstream services can
 * fetch and cache the RSA public key for JWT validation.
 *
 * GET /.well-known/jwks.json  →  no auth required
 */
@RestController
@RequiredArgsConstructor
public class JwksController {

    private final SecurityConfig securityConfig;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        RSAKey rsaKey = new RSAKey.Builder(securityConfig.loadPublicKey())
                .keyID("auth-key-1") // kid — used during key rotation
                .build();
        return new JWKSet(rsaKey).toJSONObject();
    }
}
