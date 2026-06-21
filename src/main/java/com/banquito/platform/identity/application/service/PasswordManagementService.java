package com.banquito.platform.identity.application.service;

import com.banquito.platform.identity.api.dto.api.ActivateAccountRequest;
import com.banquito.platform.identity.api.dto.api.ChangePasswordRequest;
import com.banquito.platform.identity.api.dto.api.ForgotPasswordRequest;
import com.banquito.platform.identity.api.dto.api.GenericResponse;
import com.banquito.platform.identity.api.dto.api.ResetPasswordRequest;
import com.banquito.platform.identity.api.dto.internal.AuthenticatedActor;
import com.banquito.platform.identity.domain.enums.EstadoSesionEnum;
import com.banquito.platform.identity.domain.enums.ResultadoAuditoriaSeguridadEnum;
import com.banquito.platform.identity.domain.model.OutboxEvent;
import com.banquito.platform.identity.domain.model.PasswordRecoveryToken;
import com.banquito.platform.identity.domain.model.SesionUsuario;
import com.banquito.platform.identity.domain.model.UsuarioIdentidad;
import com.banquito.platform.identity.domain.repository.OutboxEventRepository;
import com.banquito.platform.identity.domain.repository.PasswordRecoveryTokenRepository;
import com.banquito.platform.identity.domain.repository.SesionUsuarioRepository;
import com.banquito.platform.identity.domain.repository.UsuarioIdentidadRepository;
import com.banquito.platform.identity.shared.exception.BusinessException;
import com.banquito.platform.identity.shared.tracing.CorrelationIdHolder;
import com.banquito.platform.identity.shared.util.HashUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class PasswordManagementService {
    private static final String GENERIC_RECOVERY_MESSAGE =
            "Si la identidad existe y está habilitada, se enviarán instrucciones de recuperación.";

    private final UsuarioIdentidadRepository usuarioRepository;
    private final SesionUsuarioRepository sesionRepository;
    private final PasswordRecoveryTokenRepository tokenRepository;
    private final OutboxEventRepository outboxRepository;
    private final PasswordEncoder passwordEncoder;
    private final ParametroSeguridadService parametroService;
    private final AuditoriaSeguridadService auditoriaService;
    private final ObjectMapper objectMapper;
    private final String customerActivationBaseUrl;
    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordManagementService(UsuarioIdentidadRepository usuarioRepository,
                                     SesionUsuarioRepository sesionRepository,
                                     PasswordRecoveryTokenRepository tokenRepository,
                                     OutboxEventRepository outboxRepository,
                                     PasswordEncoder passwordEncoder,
                                     ParametroSeguridadService parametroService,
                                     AuditoriaSeguridadService auditoriaService,
                                     ObjectMapper objectMapper,
                                     @Value("${banquito.onboarding.customer-activation-base-url:http://localhost:5174/activar}") String customerActivationBaseUrl) {
        this.usuarioRepository = usuarioRepository;
        this.sesionRepository = sesionRepository;
        this.tokenRepository = tokenRepository;
        this.outboxRepository = outboxRepository;
        this.passwordEncoder = passwordEncoder;
        this.parametroService = parametroService;
        this.auditoriaService = auditoriaService;
        this.objectMapper = objectMapper;
        this.customerActivationBaseUrl = customerActivationBaseUrl;
    }

    @Transactional
    public GenericResponse changePassword(AuthenticatedActor actor,
                                          ChangePasswordRequest request,
                                          String ip,
                                          String userAgent) {
        UsuarioIdentidad usuario = requireHumanUser(actor);
        if (usuario.getPasswordHash() == null || !passwordEncoder.matches(request.currentPassword(), usuario.getPasswordHash())) {
            auditoriaService.registrarUsuario(usuario, "PASSWORD_CHANGE_DENIED", ResultadoAuditoriaSeguridadEnum.DENEGADO,
                    ip, userAgent, "{\"reason\":\"invalid_current_password\"}");
            throw new BusinessException("AUTH_CURRENT_PASSWORD_INVALID", "La contraseña actual es incorrecta", HttpStatus.UNPROCESSABLE_ENTITY);
        }
        validateNewPassword(usuario, request.newPassword());
        updatePassword(usuario, request.newPassword());
        invalidateActiveSessions(usuario, "Cambio voluntario de contraseña");
        invalidateRecoveryTokens(usuario, LocalDateTime.now());
        auditoriaService.registrarUsuario(usuario, "PASSWORD_CHANGED", ResultadoAuditoriaSeguridadEnum.OK, ip, userAgent, null);
        return new GenericResponse("PASSWORD_CHANGED", "La contraseña fue actualizada. Debe iniciar sesión nuevamente.");
    }

    @Transactional
    public GenericResponse forgotPassword(ForgotPasswordRequest request, String ip, String userAgent) {
        String value = request.usernameOrEmail().trim();
        UsuarioIdentidad usuario = usuarioRepository.findByUsernameIgnoreCase(value)
                .or(() -> usuarioRepository.findByEmailIgnoreCase(value))
                .orElse(null);

        if (usuario == null || !usuario.estaActivo() || usuario.getEmail() == null || usuario.getEmail().isBlank()) {
            auditoriaService.registrarSistema("PASSWORD_RECOVERY_REQUEST_IGNORED", ResultadoAuditoriaSeguridadEnum.ALERTA,
                    "{\"reason\":\"identity_not_eligible\"}");
            return new GenericResponse("PASSWORD_RECOVERY_REQUESTED", GENERIC_RECOVERY_MESSAGE);
        }

        LocalDateTime now = LocalDateTime.now();
        invalidateRecoveryTokens(usuario, now);
        String rawToken = secureToken();
        int expirationMinutes = parametroService.getInteger("PASSWORD_RESET_TOKEN_MINUTES", 15);
        PasswordRecoveryToken token = PasswordRecoveryToken.crear(
                usuario, HashUtil.sha256(rawToken), now.plusMinutes(expirationMinutes), ip, userAgent);
        tokenRepository.saveAndFlush(token);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("notificationType", "PASSWORD_RESET_REQUESTED");
        payload.put("recipient", usuario.getEmail());
        payload.put("username", usuario.getUsername());
        payload.put("resetToken", rawToken);
        payload.put("expiresInMinutes", expirationMinutes);
        payload.put("correlationId", CorrelationIdHolder.get());
        outboxRepository.saveAndFlush(OutboxEvent.pendiente(
                CorrelationIdHolder.get(), "PASSWORD_RESET_REQUESTED", "USUARIO_IDENTIDAD",
                usuario.getUuidUsuario(), writeJson(payload)));

        auditoriaService.registrarUsuario(usuario, "PASSWORD_RECOVERY_REQUESTED", ResultadoAuditoriaSeguridadEnum.OK,
                ip, userAgent, "{\"delivery\":\"email\"}");
        return new GenericResponse("PASSWORD_RECOVERY_REQUESTED", GENERIC_RECOVERY_MESSAGE);
    }

    @Transactional
    public GenericResponse activateAccount(ActivateAccountRequest request, String ip, String userAgent) {
        PasswordRecoveryToken token = tokenRepository.findByTokenHash(HashUtil.sha256(request.token().trim()))
                .orElseThrow(() -> new BusinessException("AUTH_ACCOUNT_ACTIVATION_TOKEN_INVALID",
                        "El token de activación es inválido o ya fue utilizado", HttpStatus.UNPROCESSABLE_ENTITY));
        LocalDateTime now = LocalDateTime.now();
        if (!token.estaVigente(now)) {
            throw new BusinessException("AUTH_ACCOUNT_ACTIVATION_TOKEN_EXPIRED",
                    "El token de activación expiró o ya fue utilizado", HttpStatus.UNPROCESSABLE_ENTITY);
        }

        UsuarioIdentidad usuario = token.getUsuario();
        if (!com.banquito.platform.identity.domain.enums.EstadoUsuarioIdentidadEnum.PENDIENTE.equals(usuario.getEstado())) {
            auditoriaService.registrarUsuario(usuario, "ACCOUNT_ACTIVATION_DENIED", ResultadoAuditoriaSeguridadEnum.DENEGADO,
                    ip, userAgent, "{\"reason\":\"identity_not_pending\"}");
            throw new BusinessException("AUTH_ACCOUNT_ALREADY_ACTIVE",
                    "La identidad no se encuentra pendiente de activación", HttpStatus.CONFLICT);
        }

        validateNewPassword(usuario, request.newPassword());
        updatePassword(usuario, request.newPassword());
        usuario.setEstado(com.banquito.platform.identity.domain.enums.EstadoUsuarioIdentidadEnum.ACTIVO);
        usuario.setEmailVerificado(true);
        usuario.setFechaActualizacion(now);
        usuarioRepository.saveAndFlush(usuario);
        token.marcarUsado(now);
        tokenRepository.saveAndFlush(token);
        invalidateRecoveryTokens(usuario, now);
        auditoriaService.registrarUsuario(usuario, "ACCOUNT_ACTIVATED", ResultadoAuditoriaSeguridadEnum.OK,
                ip, userAgent, "{\"channel\":\"email_token\"}");
        return new GenericResponse("ACCOUNT_ACTIVATED", "La cuenta fue activada correctamente. Ya puede iniciar sesión.");
    }

    @Transactional
    public GenericResponse resetPassword(ResetPasswordRequest request, String ip, String userAgent) {
        PasswordRecoveryToken token = tokenRepository.findByTokenHash(HashUtil.sha256(request.token().trim()))
                .orElseThrow(() -> new BusinessException("AUTH_PASSWORD_RESET_TOKEN_INVALID",
                        "El token de recuperación es inválido o ya fue utilizado", HttpStatus.UNPROCESSABLE_ENTITY));
        LocalDateTime now = LocalDateTime.now();
        if (!token.estaVigente(now)) {
            throw new BusinessException("AUTH_PASSWORD_RESET_TOKEN_EXPIRED",
                    "El token de recuperación expiró o ya fue utilizado", HttpStatus.UNPROCESSABLE_ENTITY);
        }

        UsuarioIdentidad usuario = token.getUsuario();
        if (!usuario.estaActivo()) {
            auditoriaService.registrarUsuario(usuario, "PASSWORD_RESET_DENIED", ResultadoAuditoriaSeguridadEnum.DENEGADO,
                    ip, userAgent, "{\"reason\":\"inactive_identity\"}");
            throw new BusinessException("AUTH_USER_NOT_ACTIVE", "La identidad no se encuentra activa", HttpStatus.FORBIDDEN);
        }

        validateNewPassword(usuario, request.newPassword());
        updatePassword(usuario, request.newPassword());
        token.marcarUsado(now);
        tokenRepository.saveAndFlush(token);
        invalidateRecoveryTokens(usuario, now);
        invalidateActiveSessions(usuario, "Restablecimiento de contraseña");
        auditoriaService.registrarUsuario(usuario, "PASSWORD_RESET_COMPLETED", ResultadoAuditoriaSeguridadEnum.OK,
                ip, userAgent, null);
        return new GenericResponse("PASSWORD_RESET_COMPLETED", "La contraseña fue restablecida correctamente.");
    }

    @Transactional
    public void issueInternalUserActivation(String userUuid, String ip, String userAgent) {
        UsuarioIdentidad usuario = usuarioRepository.findByUuidUsuario(userUuid)
                .orElseThrow(() -> new BusinessException("IAM_USER_NOT_FOUND", "Usuario no encontrado", HttpStatus.NOT_FOUND));
        LocalDateTime now = LocalDateTime.now();
        invalidateRecoveryTokens(usuario, now);
        String rawToken = secureToken();
        int expirationMinutes = parametroService.getInteger("PASSWORD_RESET_TOKEN_MINUTES", 15);
        PasswordRecoveryToken token = PasswordRecoveryToken.crear(
                usuario, HashUtil.sha256(rawToken), now.plusMinutes(expirationMinutes), ip, userAgent);
        tokenRepository.saveAndFlush(token);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("notificationType", "INTERNAL_USER_ONBOARDING_COMPLETED");
        payload.put("recipient", usuario.getEmail());
        payload.put("username", usuario.getUsername());
        payload.put("activationToken", rawToken);
        payload.put("expiresInMinutes", expirationMinutes);
        payload.put("correlationId", CorrelationIdHolder.get());
        outboxRepository.saveAndFlush(OutboxEvent.pendiente(
                CorrelationIdHolder.get(), "INTERNAL_USER_ONBOARDING_COMPLETED", "USUARIO_IDENTIDAD",
                usuario.getUuidUsuario(), writeJson(payload)));
        auditoriaService.registrarUsuario(usuario, "INTERNAL_USER_ACTIVATION_ISSUED", ResultadoAuditoriaSeguridadEnum.OK,
                ip, userAgent, null);
    }

    @Transactional
    public void issueCustomerUserActivation(String userUuid, String recipientName, String customerType, boolean switchAccess, String ip, String userAgent) {
        UsuarioIdentidad usuario = usuarioRepository.findByUuidUsuario(userUuid)
                .orElseThrow(() -> new BusinessException("IAM_USER_NOT_FOUND", "Usuario no encontrado", HttpStatus.NOT_FOUND));
        if (usuario.getEmail() == null || usuario.getEmail().isBlank()) {
            throw new BusinessException("IAM_CUSTOMER_EMAIL_REQUIRED", "El usuario cliente requiere correo electrónico para activación", HttpStatus.UNPROCESSABLE_ENTITY);
        }
        LocalDateTime now = LocalDateTime.now();
        invalidateRecoveryTokens(usuario, now);
        String rawToken = secureToken();
        int expirationMinutes = parametroService.getInteger("CUSTOMER_ACTIVATION_TOKEN_MINUTES", 1440);
        PasswordRecoveryToken token = PasswordRecoveryToken.crear(
                usuario, HashUtil.sha256(rawToken), now.plusMinutes(expirationMinutes), ip, userAgent);
        tokenRepository.saveAndFlush(token);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("notificationType", "CUSTOMER_USER_ACTIVATION_REQUESTED");
        payload.put("recipient", usuario.getEmail());
        payload.put("recipientName", recipientName == null || recipientName.isBlank() ? usuario.getUsername() : recipientName);
        payload.put("username", usuario.getUsername());
        payload.put("activationToken", rawToken);
        payload.put("expiresInMinutes", expirationMinutes);
        payload.put("customerType", customerType);
        payload.put("switchAccessEnabled", switchAccess);
        payload.put("activationUrl", activationUrl(rawToken));
        payload.put("correlationId", CorrelationIdHolder.get());
        outboxRepository.saveAndFlush(OutboxEvent.pendiente(
                CorrelationIdHolder.get(), "CUSTOMER_USER_ACTIVATION_REQUESTED", "USUARIO_IDENTIDAD",
                usuario.getUuidUsuario(), writeJson(payload)));
        auditoriaService.registrarUsuario(usuario, "CUSTOMER_USER_ACTIVATION_ISSUED", ResultadoAuditoriaSeguridadEnum.OK,
                ip, userAgent, "{\"delivery\":\"email\"}");
    }

    private UsuarioIdentidad requireHumanUser(AuthenticatedActor actor) {
        if (actor == null || actor.subject() == null || "SERVICIO".equalsIgnoreCase(actor.actorType())) {
            throw new BusinessException("AUTH_HUMAN_IDENTITY_REQUIRED", "La operación requiere una identidad humana autenticada", HttpStatus.FORBIDDEN);
        }
        return usuarioRepository.findByUuidUsuario(actor.subject())
                .orElseThrow(() -> new BusinessException("IAM_USER_NOT_FOUND", "Usuario no encontrado", HttpStatus.NOT_FOUND));
    }

    private void validateNewPassword(UsuarioIdentidad usuario, String newPassword) {
        int minLength = parametroService.getInteger("PASSWORD_MIN_LENGTH", 10);
        if (newPassword == null || newPassword.length() < minLength) {
            throw new BusinessException("AUTH_PASSWORD_POLICY_VIOLATION",
                    "La nueva contraseña debe tener al menos " + minLength + " caracteres", HttpStatus.UNPROCESSABLE_ENTITY);
        }
        boolean hasUpper = newPassword.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = newPassword.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = newPassword.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = newPassword.chars().anyMatch(ch -> !Character.isLetterOrDigit(ch));
        if (!(hasUpper && hasLower && hasDigit && hasSpecial)) {
            throw new BusinessException("AUTH_PASSWORD_POLICY_VIOLATION",
                    "La nueva contraseña debe combinar mayúsculas, minúsculas, números y un carácter especial", HttpStatus.UNPROCESSABLE_ENTITY);
        }
        if (usuario.getPasswordHash() != null && passwordEncoder.matches(newPassword, usuario.getPasswordHash())) {
            throw new BusinessException("AUTH_PASSWORD_REUSE_NOT_ALLOWED",
                    "La nueva contraseña debe ser diferente a la contraseña actual", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    private void updatePassword(UsuarioIdentidad usuario, String newPassword) {
        usuario.setPasswordHash(passwordEncoder.encode(newPassword));
        usuario.setPasswordAlgorithm("BCrypt");
        usuario.setPasswordUpdatedAt(LocalDateTime.now());
        usuario.setRequiereCambioPassword(false);
        usuario.setIntentosFallidos(0);
        usuario.setBloqueadoHasta(null);
        usuario.setFechaActualizacion(LocalDateTime.now());
        usuarioRepository.saveAndFlush(usuario);
    }

    private void invalidateActiveSessions(UsuarioIdentidad usuario, String reason) {
        List<SesionUsuario> sessions = sesionRepository.findByUsuarioAndEstado(usuario, EstadoSesionEnum.ACTIVA);
        sessions.forEach(session -> session.revocar(reason));
        if (!sessions.isEmpty()) {
            sesionRepository.saveAllAndFlush(sessions);
        }
    }

    private void invalidateRecoveryTokens(UsuarioIdentidad usuario, LocalDateTime now) {
        List<PasswordRecoveryToken> active = tokenRepository.findByUsuarioAndFechaUsoIsNull(usuario);
        active.forEach(token -> token.marcarUsado(now));
        if (!active.isEmpty()) {
            tokenRepository.saveAllAndFlush(active);
        }
    }

    private String activationUrl(String token) {
        String base = customerActivationBaseUrl == null || customerActivationBaseUrl.isBlank()
                ? "http://localhost:5174/activar"
                : customerActivationBaseUrl.trim();
        return base + (base.contains("?") ? "&" : "?") + "token=" + token;
    }

    private String secureToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String writeJson(Object payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception ex) {
            throw new IllegalStateException("No fue posible serializar el evento de recuperación", ex);
        }
    }
}
