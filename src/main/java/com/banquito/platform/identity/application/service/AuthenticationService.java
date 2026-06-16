package com.banquito.platform.identity.application.service;

import com.banquito.platform.identity.api.dto.api.*;
import com.banquito.platform.identity.domain.enums.*;
import com.banquito.platform.identity.domain.model.*;
import com.banquito.platform.identity.domain.repository.*;
import com.banquito.platform.identity.infrastructure.security.JwtService;
import com.banquito.platform.identity.shared.exception.BusinessException;
import com.banquito.platform.identity.shared.util.HashUtil;
import com.banquito.platform.identity.api.dto.internal.AuthenticatedActor;
import io.jsonwebtoken.Claims;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
public class AuthenticationService {
    private final UsuarioIdentidadRepository usuarioRepository;
    private final SesionUsuarioRepository sesionRepository;
    private final ApiClientRepository apiClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final PermissionQueryService permissionQueryService;
    private final ParametroSeguridadService parametroService;
    private final AuditoriaSeguridadService auditoriaService;
    private final SecureRandom secureRandom = new SecureRandom();

    public AuthenticationService(UsuarioIdentidadRepository usuarioRepository,
                                 SesionUsuarioRepository sesionRepository,
                                 ApiClientRepository apiClientRepository,
                                 PasswordEncoder passwordEncoder,
                                 JwtService jwtService,
                                 PermissionQueryService permissionQueryService,
                                 ParametroSeguridadService parametroService,
                                 AuditoriaSeguridadService auditoriaService) {
        this.usuarioRepository = usuarioRepository;
        this.sesionRepository = sesionRepository;
        this.apiClientRepository = apiClientRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.permissionQueryService = permissionQueryService;
        this.parametroService = parametroService;
        this.auditoriaService = auditoriaService;
    }

    @Transactional
    public TokenResponse login(LoginRequest request, String ip, String userAgent) {
        UsuarioIdentidad usuario = usuarioRepository.findByUsername(request.username())
                .orElseThrow(() -> new BusinessException("AUTH_INVALID_CREDENTIALS", "Usuario o contraseña incorrectos", HttpStatus.UNAUTHORIZED));

        LocalDateTime ahora = LocalDateTime.now();
        if (!usuario.estaActivo() || usuario.estaBloqueadoTemporalmente(ahora)) {
            auditoriaService.registrarUsuario(usuario, "LOGIN_DENIED", ResultadoAuditoriaSeguridadEnum.DENEGADO, ip, userAgent, "{\"reason\":\"inactive_or_blocked\"}");
            throw new BusinessException("AUTH_USER_NOT_ACTIVE", "La identidad no se encuentra activa para iniciar sesión", HttpStatus.FORBIDDEN);
        }

        if (usuario.getPasswordHash() == null || !passwordEncoder.matches(request.password(), usuario.getPasswordHash())) {
            int maxIntentos = parametroService.getInteger("MAX_FAILED_ATTEMPTS", 5);
            usuario.registrarLoginFallido(maxIntentos, ahora.plusMinutes(15));
            usuarioRepository.save(usuario);
            auditoriaService.registrarUsuario(usuario, "LOGIN_FAILED", ResultadoAuditoriaSeguridadEnum.ERROR, ip, userAgent, "{\"reason\":\"bad_credentials\"}");
            throw new BusinessException("AUTH_INVALID_CREDENTIALS", "Usuario o contraseña incorrectos", HttpStatus.UNAUTHORIZED);
        }

        usuario.registrarLoginExitoso(ahora);
        usuarioRepository.save(usuario);

        List<String> roles = permissionQueryService.rolesActivos(usuario);
        List<String> scopes = permissionQueryService.scopesActivos(usuario);
        String jti = jwtService.newJti();
        String accessToken = jwtService.generateUserAccessToken(usuario, jti, roles, scopes);
        String refreshToken = secureToken();

        SesionUsuario sesion = new SesionUsuario();
        sesion.setUuidSesion(UUID.randomUUID().toString());
        sesion.setUsuario(usuario);
        sesion.setAccessTokenJti(jti);
        sesion.setRefreshTokenHash(HashUtil.sha256(refreshToken));
        sesion.setIpOrigen(ip);
        sesion.setUserAgent(userAgent);
        sesion.setEstado(EstadoSesionEnum.ACTIVA);
        sesion.setFechaInicio(ahora);
        sesion.setFechaExpiracion(ahora.plusDays(jwtService.refreshTokenDays()));
        sesionRepository.save(sesion);

        auditoriaService.registrarUsuario(usuario, "LOGIN_SUCCESS", ResultadoAuditoriaSeguridadEnum.OK, ip, userAgent, null);
        return tokenResponse(accessToken, refreshToken, sesion.getUuidSesion(), usuario, roles, scopes);
    }

    @Transactional
    public TokenResponse refresh(RefreshTokenRequest request, String ip, String userAgent) {
        String hash = HashUtil.sha256(request.refreshToken());
        SesionUsuario sesion = sesionRepository.findByRefreshTokenHashAndEstado(hash, EstadoSesionEnum.ACTIVA)
                .orElseThrow(() -> new BusinessException("AUTH_INVALID_REFRESH", "Refresh token inválido o revocado", HttpStatus.UNAUTHORIZED));
        if (sesion.getFechaExpiracion().isBefore(LocalDateTime.now())) {
            sesion.setEstado(EstadoSesionEnum.EXPIRADA);
            sesionRepository.save(sesion);
            throw new BusinessException("AUTH_REFRESH_EXPIRED", "Refresh token expirado", HttpStatus.UNAUTHORIZED);
        }
        UsuarioIdentidad usuario = sesion.getUsuario();
        if (!usuario.estaActivo()) {
            throw new BusinessException("AUTH_USER_NOT_ACTIVE", "La identidad no se encuentra activa", HttpStatus.FORBIDDEN);
        }

        List<String> roles = permissionQueryService.rolesActivos(usuario);
        List<String> scopes = permissionQueryService.scopesActivos(usuario);
        String jti = jwtService.newJti();
        String accessToken = jwtService.generateUserAccessToken(usuario, jti, roles, scopes);
        String refreshToken = secureToken();
        sesion.setAccessTokenJti(jti);
        sesion.setRefreshTokenHash(HashUtil.sha256(refreshToken));
        sesion.setIpOrigen(ip);
        sesion.setUserAgent(userAgent);
        sesionRepository.save(sesion);
        auditoriaService.registrarUsuario(usuario, "TOKEN_REFRESH", ResultadoAuditoriaSeguridadEnum.OK, ip, userAgent, null);
        return tokenResponse(accessToken, refreshToken, sesion.getUuidSesion(), usuario, roles, scopes);
    }

    @Transactional
    public void logout(LogoutRequest request, String ip, String userAgent) {
        if (request == null) {
            throw new BusinessException("AUTH_LOGOUT_REQUEST_REQUIRED", "La solicitud de cierre de sesión es obligatoria", HttpStatus.BAD_REQUEST);
        }

        SesionUsuario sesion;
        if (request.sessionUuid() != null && !request.sessionUuid().isBlank()) {
            sesion = sesionRepository.findByUuidSesion(request.sessionUuid()).orElse(null);
        } else if (request.accessToken() != null && !request.accessToken().isBlank()) {
            Claims claims = jwtService.parseClaims(cleanBearer(request.accessToken()));
            sesion = sesionRepository.findByAccessTokenJti(claims.getId()).orElse(null);
        } else if (request.refreshToken() != null && !request.refreshToken().isBlank()) {
            sesion = sesionRepository.findByRefreshTokenHashAndEstado(HashUtil.sha256(request.refreshToken()), EstadoSesionEnum.ACTIVA).orElse(null);
        } else {
            throw new BusinessException("AUTH_LOGOUT_TOKEN_REQUIRED", "Debe enviar sessionUuid, accessToken o refreshToken para cerrar sesión", HttpStatus.BAD_REQUEST);
        }

        if (sesion == null) {
            throw new BusinessException("AUTH_SESSION_NOT_FOUND", "No se encontró una sesión activa asociada a la solicitud", HttpStatus.NOT_FOUND);
        }
        if (sesion.getEstado() != EstadoSesionEnum.ACTIVA) {
            throw new BusinessException("AUTH_SESSION_ALREADY_CLOSED", "La sesión ya no se encuentra activa", HttpStatus.CONFLICT);
        }

        sesion.revocar("Logout solicitado");
        sesionRepository.save(sesion);
        auditoriaService.registrarUsuario(sesion.getUsuario(), "LOGOUT", ResultadoAuditoriaSeguridadEnum.OK, ip, userAgent, null);
    }

    @Transactional(readOnly = true)
    public TokenIntrospectionResponse introspect(TokenIntrospectionRequest request) {
        try {
            Claims claims = jwtService.parseClaims(cleanBearer(request.token()));
            List<String> scopes = claims.get("scopes", List.class);
            List<String> roles = claims.get("roles", List.class);
            scopes = scopes == null ? List.of() : scopes;
            roles = roles == null ? List.of() : roles;

            if (!isAccessTokenSessionActive(claims)) {
                return inactiveIntrospection();
            }

            boolean hasScope = request.requiredScope() == null
                    || request.requiredScope().isBlank()
                    || scopes.contains(request.requiredScope());
            if (!hasScope) {
                return new TokenIntrospectionResponse(
                        false,
                        claims.getSubject(),
                        (String) claims.get("actorType"),
                        (String) claims.get("username"),
                        (String) claims.get("clientId"),
                        roles,
                        scopes,
                        null
                );
            }

            Long expiration = claims.getExpiration() == null
                    ? null
                    : claims.getExpiration().toInstant().getEpochSecond();
            return new TokenIntrospectionResponse(
                    true,
                    claims.getSubject(),
                    (String) claims.get("actorType"),
                    (String) claims.get("username"),
                    (String) claims.get("clientId"),
                    roles,
                    scopes,
                    expiration
            );
        } catch (Exception e) {
            return inactiveIntrospection();
        }
    }

    @Transactional
    public TokenResponse clientToken(ClientTokenRequest request, String ip, String userAgent) {
        ApiClient client = apiClientRepository.findByClientId(request.clientId())
                .orElseThrow(() -> new BusinessException("AUTH_CLIENT_NOT_FOUND", "Cliente técnico no autorizado", HttpStatus.UNAUTHORIZED));
        if (!client.estaActivo(LocalDateTime.now()) || !passwordEncoder.matches(request.clientSecret(), client.getClientSecretHash())) {
            auditoriaService.registrarClienteTecnico(client, "CLIENT_AUTH_FAILED", ResultadoAuditoriaSeguridadEnum.DENEGADO, ip, userAgent, null);
            throw new BusinessException("AUTH_CLIENT_INVALID", "Credenciales de cliente técnico inválidas", HttpStatus.UNAUTHORIZED);
        }
        if (!permissionQueryService.apiClientTieneScope(client, request.requiredScope())) {
            auditoriaService.registrarClienteTecnico(client, "CLIENT_SCOPE_DENIED", ResultadoAuditoriaSeguridadEnum.DENEGADO, ip, userAgent, "{\"scope\":\"" + request.requiredScope() + "\"}");
            throw new BusinessException("AUTH_SCOPE_DENIED", "El cliente técnico no posee el scope requerido", HttpStatus.FORBIDDEN);
        }
        List<String> scopes = permissionQueryService.scopesActivos(client);
        String token = jwtService.generateClientAccessToken(client, jwtService.newJti(), scopes);
        auditoriaService.registrarClienteTecnico(client, "CLIENT_AUTH_SUCCESS", ResultadoAuditoriaSeguridadEnum.OK, ip, userAgent, null);
        return new TokenResponse(token, null, "Bearer", jwtService.accessTokenSeconds(), null, client.getClientId(), "SERVICIO", List.of("SERVICE_CLIENT"), scopes, null, "SERVICE", null);
    }

    @Transactional(readOnly = true)
    public AuthenticatedSessionResponse me(AuthenticatedActor actor) {
        if (actor == null) {
            throw new BusinessException("AUTH_SESSION_REQUIRED", "No se encontró una sesión autenticada", HttpStatus.UNAUTHORIZED);
        }
        return new AuthenticatedSessionResponse(
                actor.subject(),
                actor.username(),
                actor.actorType(),
                actor.clientId(),
                actor.roles(),
                actor.scopes(),
                actor.referenceUuid(),
                actor.referenceType(),
                actor.customerUuid()
        );
    }

    private boolean isAccessTokenSessionActive(Claims claims) {
        String actorType = (String) claims.get("actorType");
        if ("SERVICIO".equalsIgnoreCase(actorType)) {
            return true;
        }

        String jti = claims.getId();
        String subject = claims.getSubject();
        if (jti == null || jti.isBlank() || subject == null || subject.isBlank()) {
            return false;
        }

        return sesionRepository.existsByAccessTokenJtiAndEstadoAndUsuario_UuidUsuario(
                jti,
                EstadoSesionEnum.ACTIVA,
                subject
        );
    }

    private TokenIntrospectionResponse inactiveIntrospection() {
        return new TokenIntrospectionResponse(
                false,
                null,
                null,
                null,
                null,
                List.of(),
                List.of(),
                null
        );
    }

    private TokenResponse tokenResponse(String accessToken, String refreshToken, String sessionUuid, UsuarioIdentidad usuario, List<String> roles, List<String> scopes) {
        String referenceUuid = blankToNull(usuario.getUuidReferenciaExterna());
        String referenceType = blankToNull(usuario.getReferenciaTipo());
        String customerUuid = "CUSTOMER".equalsIgnoreCase(referenceType) ? referenceUuid : null;
        return new TokenResponse(
                accessToken,
                refreshToken,
                "Bearer",
                jwtService.accessTokenSeconds(),
                sessionUuid,
                usuario.getUuidUsuario(),
                usuario.getTipoActor().getValue(),
                roles,
                scopes,
                referenceUuid,
                referenceType,
                customerUuid
        );
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private String secureToken() {
        byte[] bytes = new byte[48];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String cleanBearer(String token) {
        return token != null && token.startsWith("Bearer ") ? token.substring(7) : token;
    }
}
