package com.programacion4.unidad5ej7.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.security.Keys;

/**
 * Firma y valida JWT con HMAC-SHA256: el subject identifica al usuario; el
 * claim de roles usa el nombre
 * definido en {@link JwtClaimNames#ROLES}. La caducidad viene de
 * {@code app.jwt.expiration-ms} (claim {@code exp}).
 */
@Service
@RequiredArgsConstructor

public class JwtService {

	private static final int MIN_SECRET_BYTES = 32;

	private final JwtProperties properties;

	private SecretKey signingKey;

	@PostConstruct
	void initSigningKey() {
		if (!"HS256".equalsIgnoreCase(properties.algorithm())) {
			throw new IllegalStateException("Solo está soportado el algoritmo HS256 (jwt.algorithm)");
		}
		byte[] keyBytes = properties.secret().getBytes(StandardCharsets.UTF_8);
		if (keyBytes.length < MIN_SECRET_BYTES) {
			throw new IllegalStateException(
					"app.jwt.secret debe tener al menos " + MIN_SECRET_BYTES + " bytes en UTF-8 para HS256");
		}
		signingKey = Keys.hmacShaKeyFor(keyBytes);
	}

	public String generateToken(UserDetails userDetails) {
		return generateAccessToken(userDetails.getUsername());
	}

	/**
	 * Parsea y verifica firma y fechas. Ante cualquier {@link JwtException}
	 * devuelve vacío (sin relanzar ni loguear detalles).
	 */
	public Optional<Claims> parseValidClaims(String token) {
		if (token == null || token.isBlank()) {
			return Optional.empty();
		}
		try {
			return Optional.of(
					Jwts.parser().verifyWith(signingKey).build().parseSignedClaims(token).getPayload());
		} catch (JwtException ignored) {
			return Optional.empty();
		}
	}

	public Optional<String> extractUsername(String token) {
		return parseValidClaims(token).map(Claims::getSubject);
	}

	public List<String> extractRoles(Claims claims) {
		Object raw = claims.get(JwtClaimNames.ROLES);
		if (raw instanceof List<?> list) {
			return list.stream().map(Object::toString).toList();
		}
		return List.of();
	}

	// metodo para generar tokens genericos

	private String generateToken(String username, long expiration, String type) {
		Instant now = Instant.now();

		return Jwts.builder()
				.subject(username)
				.claim("type", type)
				.issuedAt(Date.from(now))
				.expiration(Date.from(now.plusMillis(expiration)))
				.signWith(signingKey)
				.compact();
	}

	public String generateAccessToken(String username) {
		return generateToken(
				username,
				properties.accessTokenExpiration(),
				"access");
	}

	public String generateRefreshToken(String username) {
		return generateToken(
				username,
				properties.refreshTokenExpiration(),
				"refresh");
	}

	public Optional<String> extractTokenType(String token) {
		return parseValidClaims(token)
				.map(claims -> claims.get("type", String.class));
	}

	public boolean isRefreshToken(String token) {
		return extractTokenType(token)
				.map(type -> type.equals("refresh"))
				.orElse(false);
	}
}
