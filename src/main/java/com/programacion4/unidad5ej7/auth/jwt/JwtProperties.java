package com.programacion4.unidad5ej7.auth.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;


@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(

        String secret,
        String algorithm,

        long accessTokenExpiration,
        long refreshTokenExpiration

) {}
