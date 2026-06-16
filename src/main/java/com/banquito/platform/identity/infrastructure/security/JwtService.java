package com.banquito.platform.identity.infrastructure.security;

import com.banquito.platform.identity.application.service.ParametroSeguridadService;
import com.banquito.platform.identity.domain.model.ApiClient;
import com.banquito.platform.identity.domain.model.UsuarioIdentidad;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class JwtService {
    private final JwtProperties properties;
    private final ParametroSeguridadService parametroSeguridadService;
    private final SecretKey key;

    public JwtService(JwtProperties properties, ParametroSeguridadService parametroSeguridadService) {
        this.properties = properties;
        this.parametroSeguridadService = parametroSeguridadService;
        this.key = Keys.hmacShaKeyFor(properties.secret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateUserAccessToken(UsuarioIdentidad user, String jti, List<String> roles, List<String> scopes) {
        Instant now = Instant.now();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("username", user.getUsername());
        claims.put("actorType", user.getTipoActor().getValue());
        claims.put("roles", roles);
        claims.put("scopes", scopes);
        if (user.getUuidReferenciaExterna() != null && !user.getUuidReferenciaExterna().isBlank()) {
            claims.put("referenceUuid", user.getUuidReferenciaExterna());
            claims.put("referenceType", user.getReferenciaTipo());
            if ("CUSTOMER".equalsIgnoreCase(user.getReferenciaTipo())) {
                claims.put("customerUuid", user.getUuidReferenciaExterna());
            }
        }
        return Jwts.builder()
                .issuer(properties.issuer())
                .subject(user.getUuidUsuario())
                .id(jti)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTokenMinutes() * 60)))
                .claims(claims)
                .signWith(key)
                .compact();
    }

    public String generateClientAccessToken(ApiClient client, String jti, List<String> scopes) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(properties.issuer())
                .subject(client.getClientId())
                .id(jti)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTokenMinutes() * 60)))
                .claims(Map.of(
                        "clientId", client.getClientId(),
                        "actorType", "SERVICIO",
                        "roles", List.of("SERVICE_CLIENT"),
                        "scopes", scopes
                ))
                .signWith(key)
                .compact();
    }

    public Claims parseClaims(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }

    public String newJti() { return UUID.randomUUID().toString(); }
    public long accessTokenSeconds() { return accessTokenMinutes() * 60; }
    public long refreshTokenDays() {
        return parametroSeguridadService.getInteger("REFRESH_TOKEN_DAYS", Math.toIntExact(properties.refreshTokenDays()));
    }

    private long accessTokenMinutes() {
        return parametroSeguridadService.getInteger("ACCESS_TOKEN_MINUTES", Math.toIntExact(properties.accessTokenMinutes()));
    }
}
