package com.banquito.platform.identity.application.service;

import com.banquito.platform.identity.api.dto.api.CreateUserRequest;
import com.banquito.platform.identity.api.dto.api.InternalUserOnboardingRequest;
import com.banquito.platform.identity.api.dto.api.InternalUserOnboardingResponse;
import com.banquito.platform.identity.api.dto.api.UserDetailResponse;
import com.banquito.platform.identity.api.dto.internal.OnboardingExecution;
import com.banquito.platform.identity.domain.enums.EstadoUsuarioIdentidadEnum;
import com.banquito.platform.identity.domain.model.UsuarioIdentidad;
import com.banquito.platform.identity.domain.repository.UsuarioIdentidadRepository;
import com.banquito.platform.identity.shared.exception.BusinessException;
import com.banquito.platform.identity.shared.tracing.CorrelationIdHolder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
public class InternalUserOnboardingService {
    private final IamManagementService iamManagementService;
    private final UsuarioIdentidadRepository usuarioRepository;
    private final PasswordManagementService passwordManagementService;
    private final InternalUserOnboardingIdempotencyService idempotencyService;
    private final RestClient adminClient;
    private final SecureRandom secureRandom = new SecureRandom();

    public InternalUserOnboardingService(IamManagementService iamManagementService,
                                         UsuarioIdentidadRepository usuarioRepository,
                                         PasswordManagementService passwordManagementService,
                                         InternalUserOnboardingIdempotencyService idempotencyService,
                                         RestClient.Builder restClientBuilder,
                                         @Value("${banquito.integrations.admin.base-url:http://localhost:8083}") String adminBaseUrl) {
        this.iamManagementService = iamManagementService;
        this.usuarioRepository = usuarioRepository;
        this.passwordManagementService = passwordManagementService;
        this.idempotencyService = idempotencyService;
        this.adminClient = restClientBuilder.baseUrl(adminBaseUrl).build();
    }

    public ExecutionResult onboard(String idempotencyKey,
                                    InternalUserOnboardingRequest request,
                                    String authorization,
                                    String ip,
                                    String userAgent) {
        OnboardingExecution start = idempotencyService.begin(idempotencyKey, request);
        if (start.replayed()) {
            return new ExecutionResult(true, start.response());
        }
        try {
            String identityUuid = start.identityUuid();
            UserDetailResponse identity;
            if (identityUuid == null) {
                identity = iamManagementService.createUser(new CreateUserRequest(
                        request.username().trim(), request.email().trim(), normalize(request.mobilePhone()),
                        temporarySecret(), "EMPLEADO", null, "USUARIO_CORE", true,
                        request.roleCodes(), "PENDIENTE"));
                identityUuid = identity.userUuid();
                idempotencyService.linkIdentity(idempotencyKey, identityUuid);
            } else {
                identity = iamManagementService.getUser(identityUuid);
            }

            AdminCoreUserResponse coreUser = createAdminProfile(identityUuid, request, authorization, idempotencyKey);
            activateIdentity(identityUuid);
            passwordManagementService.issueInternalUserActivation(identityUuid, ip, userAgent);

            InternalUserOnboardingResponse response = new InternalUserOnboardingResponse(
                    identityUuid, coreUser.userCoreUuid(), identity.username(), identity.email(),
                    coreUser.branchCode(), coreUser.fullName(), coreUser.position(), identity.roles(),
                    "ACTIVO", true);
            idempotencyService.complete(idempotencyKey, response);
            return new ExecutionResult(false, response);
        } catch (Exception ex) {
            idempotencyService.fail(idempotencyKey, ex);
            if (ex instanceof BusinessException businessException) throw businessException;
            if (ex instanceof RestClientResponseException remote) {
                throw new BusinessException("ONBOARDING_ADMIN_PROFILE_FAILED",
                        "No fue posible completar el perfil administrativo: HTTP " + remote.getStatusCode().value(), HttpStatus.BAD_GATEWAY);
            }
            throw new BusinessException("ONBOARDING_INTERNAL_USER_FAILED",
                    "No fue posible completar el onboarding del usuario interno", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private AdminCoreUserResponse createAdminProfile(String identityUuid,
                                                       InternalUserOnboardingRequest request,
                                                       String authorization,
                                                       String idempotencyKey) {
        if (authorization == null || authorization.isBlank()) {
            throw new BusinessException("AUTH_TOKEN_REQUIRED", "Se requiere el token del operador para completar el onboarding", HttpStatus.UNAUTHORIZED);
        }
        return adminClient.post()
                .uri("/api/v1/admin/users")
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .header("X-Correlation-Id", CorrelationIdHolder.get())
                .header("Idempotency-Key", idempotencyKey)
                .body(new AdminCoreUserRequest(identityUuid, normalize(request.branchCode()), request.fullName().trim(), normalize(request.position()), "ACTIVO"))
                .retrieve()
                .body(AdminCoreUserResponse.class);
    }

    private void activateIdentity(String identityUuid) {
        UsuarioIdentidad user = usuarioRepository.findByUuidUsuario(identityUuid)
                .orElseThrow(() -> new BusinessException("IAM_USER_NOT_FOUND", "Usuario no encontrado", HttpStatus.NOT_FOUND));
        user.setEstado(EstadoUsuarioIdentidadEnum.ACTIVO);
        user.setRequiereCambioPassword(true);
        user.setFechaActualizacion(LocalDateTime.now());
        usuarioRepository.saveAndFlush(user);
    }

    private String temporarySecret() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return "Tmp!" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String normalize(String value) {
        if (value == null) return null;
        String result = value.trim();
        return result.isBlank() ? null : result;
    }

    private record AdminCoreUserRequest(String identityUuid, String branchCode, String fullName, String position, String status) {}
    private record AdminCoreUserResponse(String userCoreUuid, String identityUuid, String branchCode, String fullName, String position, String status) {}
    public record ExecutionResult(boolean replayed, InternalUserOnboardingResponse response) {}
}
