package com.banquito.platform.identity.application.service;

import com.banquito.platform.identity.api.dto.api.CustomerUserAccessSummaryResponse;
import com.banquito.platform.identity.api.dto.api.CustomerUserOnboardingRequest;
import com.banquito.platform.identity.api.dto.api.CustomerUserOnboardingResponse;
import com.banquito.platform.identity.domain.enums.EstadoAsignacionRolEnum;
import com.banquito.platform.identity.domain.enums.EstadoUsuarioIdentidadEnum;
import com.banquito.platform.identity.domain.enums.TipoActorEnum;
import com.banquito.platform.identity.domain.model.Rol;
import com.banquito.platform.identity.domain.model.UsuarioIdentidad;
import com.banquito.platform.identity.domain.model.UsuarioRol;
import com.banquito.platform.identity.domain.repository.RolRepository;
import com.banquito.platform.identity.domain.repository.UsuarioIdentidadRepository;
import com.banquito.platform.identity.domain.repository.UsuarioRolRepository;
import com.banquito.platform.identity.shared.exception.BusinessException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.Normalizer;
import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

@Service
public class CustomerUserOnboardingService {
    private static final String REFERENCE_TYPE_CUSTOMER = "CUSTOMER";
    private static final String ROLE_PERSON = "CLIENTE_PERSONA";
    private static final String ROLE_COMPANY = "CLIENTE_EMPRESA";
    private static final String ROLE_COMPANY_MASS_PAYMENTS = "CLIENTE_EMPRESA_PAGOS_MASIVOS";

    private final UsuarioIdentidadRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final UsuarioRolRepository usuarioRolRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordManagementService passwordManagementService;
    private final AuditoriaSeguridadService auditoriaService;

    public CustomerUserOnboardingService(UsuarioIdentidadRepository usuarioRepository,
                                         RolRepository rolRepository,
                                         UsuarioRolRepository usuarioRolRepository,
                                         PasswordEncoder passwordEncoder,
                                         PasswordManagementService passwordManagementService,
                                         AuditoriaSeguridadService auditoriaService) {
        this.usuarioRepository = usuarioRepository;
        this.rolRepository = rolRepository;
        this.usuarioRolRepository = usuarioRolRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordManagementService = passwordManagementService;
        this.auditoriaService = auditoriaService;
    }

    @Transactional
    public CustomerUserOnboardingResponse onboard(CustomerUserOnboardingRequest request, String ip, String userAgent) {
        String customerUuid = required(request.customerUuid(), "customerUuid");
        String customerType = normalizeCustomerType(request.customerType());
        String email = required(request.email(), "email").toLowerCase(Locale.ROOT);
        String displayName = required(request.displayName(), "displayName");
        boolean switchAccess = Boolean.TRUE.equals(request.switchAccessEnabled());
        boolean massPaymentsEnabled = Boolean.TRUE.equals(request.massPaymentsEnabled());

        if (switchAccess && !"JURIDICO".equals(customerType)) {
            throw new BusinessException("IAM_SWITCH_ACCESS_ONLY_COMPANY",
                    "El acceso al portal de pagos masivos solo aplica a clientes jurídicos", HttpStatus.UNPROCESSABLE_ENTITY);
        }
        if (switchAccess && !massPaymentsEnabled) {
            throw new BusinessException("IAM_SWITCH_ACCESS_REQUIRES_MASS_PAYMENTS",
                    "La empresa debe tener pagos masivos habilitados antes de crear el acceso al portal Switch", HttpStatus.UNPROCESSABLE_ENTITY);
        }

        List<UsuarioIdentidad> existing = usuarioRepository.findByUuidReferenciaExternaAndReferenciaTipo(customerUuid, REFERENCE_TYPE_CUSTOMER);
        if (!existing.isEmpty()) {
            UsuarioIdentidad user = existing.get(0);
            ensureEmailAvailableForUser(email, user);
            assignRoles(user, desiredRoles(customerType, switchAccess));
            user.setEmail(email);
            user.setTelefonoMovil(normalizeOptional(request.mobilePhone()));
            user.setFechaActualizacion(LocalDateTime.now());
            usuarioRepository.saveAndFlush(user);
            boolean issued = EstadoUsuarioIdentidadEnum.PENDIENTE.equals(user.getEstado());
            if (issued) {
                passwordManagementService.issueCustomerUserActivation(user.getUuidUsuario(), displayName, customerType, switchAccess, ip, userAgent);
            }
            auditoriaService.registrarUsuario(user, "CUSTOMER_DIGITAL_ACCESS_UPDATED",
                    com.banquito.platform.identity.domain.enums.ResultadoAuditoriaSeguridadEnum.OK, ip, userAgent,
                    "{\"customerUuid\":\"" + customerUuid + "\",\"switchAccess\":" + switchAccess + "}");
            return toResponse(user, customerType, issued, issued
                    ? "Acceso digital pendiente. Se reemitió el correo de activación."
                    : "Acceso digital existente actualizado.");
        }

        ensureEmailNotUsed(email);
        LocalDateTime now = LocalDateTime.now();
        UsuarioIdentidad user = new UsuarioIdentidad();
        user.setUuidUsuario(UUID.randomUUID().toString());
        user.setTipoActor(TipoActorEnum.CLIENTE);
        user.setUsername(uniqueUsername(request.username(), displayName, request.identification(), customerType));
        user.setEmail(email);
        user.setEmailVerificado(false);
        user.setTelefonoMovil(normalizeOptional(request.mobilePhone()));
        user.setPasswordHash(passwordEncoder.encode(UUID.randomUUID().toString() + "!Tmp1"));
        user.setPasswordAlgorithm("BCrypt");
        user.setPasswordUpdatedAt(now);
        user.setRequiereCambioPassword(true);
        user.setEstado(EstadoUsuarioIdentidadEnum.PENDIENTE);
        user.setIntentosFallidos(0);
        user.setBloqueadoHasta(null);
        user.setUuidReferenciaExterna(customerUuid);
        user.setReferenciaTipo(REFERENCE_TYPE_CUSTOMER);
        user.setFechaCreacion(now);
        user.setFechaActualizacion(now);
        user.setVersion(0);
        UsuarioIdentidad saved = usuarioRepository.saveAndFlush(user);
        assignRoles(saved, desiredRoles(customerType, switchAccess));
        passwordManagementService.issueCustomerUserActivation(saved.getUuidUsuario(), displayName, customerType, switchAccess, ip, userAgent);
        auditoriaService.registrarUsuario(saved, "CUSTOMER_DIGITAL_ACCESS_CREATED",
                com.banquito.platform.identity.domain.enums.ResultadoAuditoriaSeguridadEnum.OK, ip, userAgent,
                "{\"customerUuid\":\"" + customerUuid + "\",\"switchAccess\":" + switchAccess + "}");
        return toResponse(saved, customerType, true, "Acceso digital creado. Se envió el correo de activación.");
    }

    @Transactional(readOnly = true)
    public CustomerUserAccessSummaryResponse findByCustomer(String customerUuid) {
        String uuid = required(customerUuid, "customerUuid");
        List<CustomerUserOnboardingResponse> users = usuarioRepository
                .findByUuidReferenciaExternaAndReferenciaTipo(uuid, REFERENCE_TYPE_CUSTOMER)
                .stream()
                .map(user -> toResponse(user, inferCustomerType(user), false, ""))
                .toList();
        return new CustomerUserAccessSummaryResponse(uuid, users);
    }

    @Transactional
    public CustomerUserOnboardingResponse resendActivation(String userUuid, String ip, String userAgent) {
        UsuarioIdentidad user = usuarioRepository.findByUuidUsuario(required(userUuid, "userUuid"))
                .orElseThrow(() -> new BusinessException("IAM_USER_NOT_FOUND", "Usuario no encontrado", HttpStatus.NOT_FOUND));
        if (!EstadoUsuarioIdentidadEnum.PENDIENTE.equals(user.getEstado())) {
            throw new BusinessException("IAM_USER_NOT_PENDING",
                    "Solo se puede reenviar activación para usuarios pendientes", HttpStatus.CONFLICT);
        }
        String customerType = inferCustomerType(user);
        boolean switchAccess = roles(user).contains(ROLE_COMPANY_MASS_PAYMENTS);
        passwordManagementService.issueCustomerUserActivation(user.getUuidUsuario(), user.getUsername(), customerType, switchAccess, ip, userAgent);
        auditoriaService.registrarUsuario(user, "CUSTOMER_ACTIVATION_RESENT",
                com.banquito.platform.identity.domain.enums.ResultadoAuditoriaSeguridadEnum.OK, ip, userAgent, null);
        return toResponse(user, customerType, true, "Correo de activación reenviado.");
    }

    private void assignRoles(UsuarioIdentidad user, Set<String> roleCodes) {
        for (String roleCode : roleCodes) {
            Rol role = rolRepository.findByCodigo(roleCode)
                    .orElseThrow(() -> new BusinessException("IAM_ROLE_NOT_FOUND", "Rol no encontrado: " + roleCode, HttpStatus.NOT_FOUND));
            usuarioRolRepository.findByUsuarioAndRolCodigo(user, roleCode).ifPresentOrElse(assignment -> {
                assignment.setEstado(EstadoAsignacionRolEnum.ACTIVO);
                assignment.setFechaRevocacion(null);
                usuarioRolRepository.save(assignment);
            }, () -> usuarioRolRepository.save(UsuarioRol.crear(user, role, "CUSTOMER_ONBOARDING")));
        }
    }

    private Set<String> desiredRoles(String customerType, boolean switchAccess) {
        Set<String> roles = new LinkedHashSet<>();
        if ("JURIDICO".equals(customerType)) {
            roles.add(ROLE_COMPANY);
            if (switchAccess) roles.add(ROLE_COMPANY_MASS_PAYMENTS);
        } else {
            roles.add(ROLE_PERSON);
        }
        return roles;
    }

    private void ensureEmailNotUsed(String email) {
        if (usuarioRepository.existsByEmailIgnoreCase(email)) {
            throw new BusinessException("IAM_EMAIL_EXISTS", "El correo ya se encuentra registrado", HttpStatus.CONFLICT);
        }
    }

    private void ensureEmailAvailableForUser(String email, UsuarioIdentidad user) {
        usuarioRepository.findByEmailIgnoreCase(email).ifPresent(existing -> {
            if (!existing.getUuidUsuario().equals(user.getUuidUsuario())) {
                throw new BusinessException("IAM_EMAIL_EXISTS", "El correo ya se encuentra registrado", HttpStatus.CONFLICT);
            }
        });
    }

    private String uniqueUsername(String requested, String displayName, String identification, String customerType) {
        String base = normalizeUsername(requested);
        if (base == null) {
            base = "JURIDICO".equals(customerType)
                    ? "empresa." + digitsOnly(identification)
                    : normalizeUsername(displayName);
        }
        if (base == null || base.length() < 4) {
            base = "cliente." + digitsOnly(identification);
        }
        String candidate = base;
        int suffix = 2;
        while (usuarioRepository.existsByUsernameIgnoreCase(candidate)) {
            candidate = base + suffix++;
        }
        return candidate;
    }

    private String normalizeUsername(String value) {
        String normalized = normalizeOptional(value);
        if (normalized == null) return null;
        normalized = Normalizer.normalize(normalized, Normalizer.Form.NFD).replaceAll("\\p{M}+", "");
        normalized = normalized.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", ".").replaceAll("^\\.+|\\.+$", "");
        if (normalized.length() > 60) normalized = normalized.substring(0, 60).replaceAll("\\.+$", "");
        return normalized.isBlank() ? null : normalized;
    }

    private String digitsOnly(String value) {
        String digits = value == null ? "" : value.replaceAll("[^0-9]", "");
        return digits.isBlank() ? UUID.randomUUID().toString().substring(0, 8) : digits;
    }

    private String inferCustomerType(UsuarioIdentidad user) {
        Set<String> current = roles(user);
        return current.contains(ROLE_COMPANY) || current.contains(ROLE_COMPANY_MASS_PAYMENTS) ? "JURIDICO" : "NATURAL";
    }

    private Set<String> roles(UsuarioIdentidad user) {
        return usuarioRolRepository.findByUsuarioAndEstado(user, EstadoAsignacionRolEnum.ACTIVO)
                .stream()
                .map(assignment -> assignment.getRol().getCodigo())
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
    }

    private CustomerUserOnboardingResponse toResponse(UsuarioIdentidad user, String customerType, boolean activationIssued, String message) {
        return new CustomerUserOnboardingResponse(
                user.getUuidUsuario(),
                user.getUsername(),
                user.getEmail(),
                user.getUuidReferenciaExterna(),
                customerType,
                user.getEstado().getValue(),
                List.copyOf(roles(user)),
                activationIssued,
                message
        );
    }

    private String normalizeCustomerType(String value) {
        String type = required(value, "customerType").toUpperCase(Locale.ROOT);
        if ("LEGAL".equals(type) || "COMPANY".equals(type)) type = "JURIDICO";
        if ("PERSON".equals(type) || "NATURAL_PERSON".equals(type)) type = "NATURAL";
        if (!"NATURAL".equals(type) && !"JURIDICO".equals(type)) {
            throw new BusinessException("IAM_CUSTOMER_TYPE_INVALID", "Tipo de cliente inválido", HttpStatus.UNPROCESSABLE_ENTITY);
        }
        return type;
    }

    private String required(String value, String field) {
        String normalized = normalizeOptional(value);
        if (normalized == null) {
            throw new BusinessException("IAM_REQUIRED_FIELD", "El campo " + field + " es obligatorio", HttpStatus.BAD_REQUEST);
        }
        return normalized;
    }

    private String normalizeOptional(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isBlank() ? null : trimmed;
    }
}
