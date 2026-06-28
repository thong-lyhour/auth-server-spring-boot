package com.hour.authserver.configuration.property;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties(prefix = "jwt")
public record RsaKeyProperties(
        Resource privateKey,
        Resource publicKey,
        long accessTokenExpiry,
        long refreshTokenExpiry,
        String issuer
) {}
