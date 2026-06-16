package com.banquito.platform.identity.application.service;

import com.banquito.platform.identity.api.dto.api.*;
import com.banquito.platform.identity.domain.enums.*;
import com.banquito.platform.identity.domain.model.*;
import com.banquito.platform.identity.domain.repository.*;
import com.banquito.platform.identity.shared.exception.BusinessException;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class IamManagementService {
    private static final int DEFAULT_PAGE_SIZE = 20;
    private static final int MAX_PAGE_SIZE = 100;

    private final UsuarioIdentidadRepository usuarioRepository;
    private final RolRepository rolRepository;
    private final PermisoRepository permisoRepository;
    private final UsuarioRolRepository usuarioRolRepository;
    private final RolPermisoRepository rolPermisoRepository;
    private final ApiClientRepository apiClientRepository;
    private final ApiClientScopeRepository apiClientScopeRepository;
    private final SesionUsuarioRepository sesionRepository;
    private final PasswordEncoder passwordEncoder;
    private final PermissionQueryService permissionQueryService;

    public IamManagementService(UsuarioIdentidadRepository usuarioRepository,
                                RolRepository rolRepository,
                                PermisoRepository permisoRepository,
                                UsuarioRolRepository usuarioRolRepository,
                                RolPermisoRepository rolPermisoRepository,
                                ApiClientRepository apiClientRepository,
                                ApiClientScopeRepository apiClientScopeRepository,
                                SesionUsuarioRepository sesionRepository,
                                PasswordEncoder passwordEncoder,
                                PermissionQueryService permissionQueryService) {
        this.usuarioRepository = usuarioRepository;
        this.rolRepository = rolRepository;
        this.permisoRepository = permisoRepository;
        this.usuarioRolRepository = usuarioRolRepository;
        this.rolPermisoRepository = rolPermisoRepository;
        this.apiClientRepository = apiClientRepository;
        this.apiClientScopeRepository = apiClientScopeRepository;
        this.sesionRepository = sesionRepository;
        this.passwordEncoder = passwordEncoder;
        this.permissionQueryService = permissionQueryService;
    }

    @Transactional
    public UserDetailResponse createUser(CreateUserRequest request) {
        String username = normalizeRequiredText(request.username(), "username");
        if (usuarioRepository.existsByUsernameIgnoreCase(username)) {
            throw new BusinessException("IAM_USERNAME_EXISTS", "El nombre de usuario ya existe", HttpStatus.CONFLICT);
        }

        String email = normalizeOptionalText(request.email());
        if (email != null && usuarioRepository.existsByEmailIgnoreCase(email)) {
            throw new BusinessException("IAM_EMAIL_EXISTS", "El correo ya se encuentra registrado", HttpStatus.CONFLICT);
        }

        TipoActorEnum actorType = parseActorType(request.actorType());
        EstadoUsuarioIdentidadEnum status = parseUserStatus(request.status(), EstadoUsuarioIdentidadEnum.ACTIVO);
        LocalDateTime now = LocalDateTime.now();

        UsuarioIdentidad usuario = new UsuarioIdentidad();
        usuario.setUuidUsuario(UUID.randomUUID().toString());
        usuario.setUsername(username);
        usuario.setEmail(email);
        usuario.setTelefonoMovil(normalizeOptionalText(request.telefonoMovil()));
        usuario.setPasswordHash(passwordEncoder.encode(request.password()));
        usuario.setPasswordAlgorithm("BCrypt");
        usuario.setPasswordUpdatedAt(now);
        usuario.setRequiereCambioPassword(Boolean.TRUE.equals(request.requirePasswordChange()));
        usuario.setEmailVerificado(false);
        usuario.setTipoActor(actorType);
        usuario.setEstado(status);
        usuario.setIntentosFallidos(0);
        usuario.setUuidReferenciaExterna(normalizeOptionalText(request.externalReferenceUuid()));
        usuario.setReferenciaTipo(normalizeOptionalText(request.referenceType()));
        usuario.setFechaCreacion(now);
        usuario.setFechaActualizacion(now);
        usuario.setVersion(0);

        UsuarioIdentidad saved = usuarioRepository.saveAndFlush(usuario);
        assignInitialRoles(saved, request.roleCodes());
        return toUserDetail(saved);
    }

    @Transactional(readOnly = true)
    public UserListResponse listUsers(String actorType,
                                      String status,
                                      String username,
                                      String search,
                                      Integer page,
                                      Integer size) {
        Pageable pageable = PageRequest.of(normalizePage(page), normalizeSize(size), Sort.by(Sort.Direction.ASC, "username"));
        TipoActorEnum actorFilter = actorType == null || actorType.isBlank() ? null : parseActorType(actorType);
        EstadoUsuarioIdentidadEnum statusFilter = status == null || status.isBlank() ? null : parseUserStatus(status, null);
        String usernameFilter = normalizeOptionalText(username);
        String searchFilter = normalizeOptionalText(search);

        Specification<UsuarioIdentidad> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (actorFilter != null) {
                predicates.add(cb.equal(root.get("tipoActor"), actorFilter));
            }
            if (statusFilter != null) {
                predicates.add(cb.equal(root.get("estado"), statusFilter));
            }
            if (usernameFilter != null) {
                predicates.add(cb.like(cb.lower(root.get("username")), "%" + usernameFilter.toLowerCase(Locale.ROOT) + "%"));
            }
            if (searchFilter != null) {
                String term = "%" + searchFilter.toLowerCase(Locale.ROOT) + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("username")), term),
                        cb.like(cb.lower(root.get("email")), term),
                        cb.like(cb.lower(root.get("telefonoMovil")), term),
                        cb.like(cb.lower(root.get("uuidReferenciaExterna")), term),
                        cb.like(cb.lower(root.get("referenciaTipo")), term)
                ));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<UsuarioIdentidad> usersPage = usuarioRepository.findAll(spec, pageable);
        List<UserSummaryResponse> users = usersPage.getContent().stream().map(this::toUserSummary).toList();
        return new UserListResponse(usersPage.getTotalElements(), usersPage.getNumber(), usersPage.getSize(), usersPage.getTotalPages(), users);
    }

    @Transactional(readOnly = true)
    public List<RoleResponse> listRoles(String status) {
        EstadoGeneralEnum statusFilter = status == null || status.isBlank() ? EstadoGeneralEnum.ACTIVO : parseGeneralStatus(status);
        return rolRepository.findByEstadoOrderByNombreAsc(statusFilter).stream()
                .map(this::toRoleResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public UserDetailResponse getUser(String userUuid) {
        UsuarioIdentidad usuario = usuarioRepository.findByUuidUsuario(userUuid)
                .orElseThrow(() -> new BusinessException("IAM_USER_NOT_FOUND", "Usuario no encontrado", HttpStatus.NOT_FOUND));
        return toUserDetail(usuario);
    }

    @Transactional(readOnly = true)
    public UserDetailResponse getUserByUsername(String username) {
        UsuarioIdentidad usuario = usuarioRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new BusinessException("IAM_USER_NOT_FOUND", "Usuario no encontrado", HttpStatus.NOT_FOUND));
        return toUserDetail(usuario);
    }

    @Transactional
    public UserDetailResponse changeUserStatus(String userUuid, ChangeUserStatusRequest request) {
        UsuarioIdentidad usuario = usuarioRepository.findByUuidUsuario(userUuid)
                .orElseThrow(() -> new BusinessException("IAM_USER_NOT_FOUND", "Usuario no encontrado", HttpStatus.NOT_FOUND));
        usuario.setEstado(parseUserStatus(request.status(), EstadoUsuarioIdentidadEnum.ACTIVO));
        usuario.setFechaActualizacion(LocalDateTime.now());
        usuarioRepository.save(usuario);
        return toUserDetail(usuario);
    }

    @Transactional
    public GenericResponse assignRole(String userUuid, AssignRoleRequest request) {
        UsuarioIdentidad usuario = usuarioRepository.findByUuidUsuario(userUuid)
                .orElseThrow(() -> new BusinessException("IAM_USER_NOT_FOUND", "Usuario no encontrado", HttpStatus.NOT_FOUND));
        Rol rol = rolRepository.findByCodigo(request.roleCode())
                .orElseThrow(() -> new BusinessException("IAM_ROLE_NOT_FOUND", "Rol no encontrado", HttpStatus.NOT_FOUND));
        usuarioRolRepository.findByUsuarioAndRolCodigo(usuario, request.roleCode()).ifPresentOrElse(ur -> {
            ur.setEstado(EstadoAsignacionRolEnum.ACTIVO);
            ur.setFechaRevocacion(null);
            usuarioRolRepository.save(ur);
        }, () -> usuarioRolRepository.save(UsuarioRol.crear(usuario, rol, request.assignedByUuid())));
        return new GenericResponse("OK", "Rol asignado correctamente");
    }

    @Transactional
    public GenericResponse revokeRole(String userUuid, String roleCode) {
        UsuarioIdentidad usuario = usuarioRepository.findByUuidUsuario(userUuid)
                .orElseThrow(() -> new BusinessException("IAM_USER_NOT_FOUND", "Usuario no encontrado", HttpStatus.NOT_FOUND));
        UsuarioRol usuarioRol = usuarioRolRepository.findByUsuarioAndRolCodigo(usuario, roleCode)
                .orElseThrow(() -> new BusinessException("IAM_ROLE_ASSIGNMENT_NOT_FOUND", "Asignación de rol no encontrada", HttpStatus.NOT_FOUND));
        usuarioRol.revocar();
        usuarioRolRepository.save(usuarioRol);
        return new GenericResponse("OK", "Rol revocado correctamente");
    }

    @Transactional
    public GenericResponse createRole(CreateRoleRequest request) {
        if (rolRepository.existsByCodigo(request.code())) {
            throw new BusinessException("IAM_ROLE_EXISTS", "El rol ya existe", HttpStatus.CONFLICT);
        }
        Rol rol = new Rol();
        rol.setCodigo(request.code());
        rol.setNombre(request.name());
        rol.setTipoRol(parseRoleType(request.roleType()));
        rol.setDescripcion(request.description());
        rol.setEstado(EstadoGeneralEnum.ACTIVO);
        rol.setFechaCreacion(LocalDateTime.now());
        rol.setFechaActualizacion(LocalDateTime.now());
        rol.setVersion(0);
        rolRepository.save(rol);
        return new GenericResponse("OK", "Rol creado correctamente");
    }

    @Transactional
    public GenericResponse createPermission(CreatePermissionRequest request) {
        if (permisoRepository.existsByCodigo(request.code())) {
            throw new BusinessException("IAM_PERMISSION_EXISTS", "El permiso ya existe", HttpStatus.CONFLICT);
        }
        Permiso permiso = new Permiso();
        permiso.setCodigo(request.code());
        permiso.setNombre(request.name());
        permiso.setModulo(request.module());
        permiso.setAccion(request.action());
        permiso.setRecurso(request.resource());
        permiso.setEstado(EstadoGeneralEnum.ACTIVO);
        permiso.setFechaCreacion(LocalDateTime.now());
        permiso.setFechaActualizacion(LocalDateTime.now());
        permiso.setVersion(0);
        permisoRepository.save(permiso);
        return new GenericResponse("OK", "Permiso creado correctamente");
    }

    @Transactional
    public GenericResponse assignPermission(String roleCode, AssignPermissionRequest request) {
        Rol rol = rolRepository.findByCodigo(roleCode)
                .orElseThrow(() -> new BusinessException("IAM_ROLE_NOT_FOUND", "Rol no encontrado", HttpStatus.NOT_FOUND));
        Permiso permiso = permisoRepository.findByCodigo(request.permissionCode())
                .orElseThrow(() -> new BusinessException("IAM_PERMISSION_NOT_FOUND", "Permiso no encontrado", HttpStatus.NOT_FOUND));
        rolPermisoRepository.findByRolAndPermisoCodigo(rol, request.permissionCode()).ifPresentOrElse(rp -> {
            rp.setEstado(EstadoGeneralEnum.ACTIVO);
            rolPermisoRepository.save(rp);
        }, () -> rolPermisoRepository.save(RolPermiso.crear(rol, permiso)));
        return new GenericResponse("OK", "Permiso asignado correctamente");
    }

    @Transactional
    public GenericResponse revokePermission(String roleCode, String permissionCode) {
        Rol rol = rolRepository.findByCodigo(roleCode)
                .orElseThrow(() -> new BusinessException("IAM_ROLE_NOT_FOUND", "Rol no encontrado", HttpStatus.NOT_FOUND));
        RolPermiso rolPermiso = rolPermisoRepository.findByRolAndPermisoCodigo(rol, permissionCode)
                .orElseThrow(() -> new BusinessException("IAM_ROLE_PERMISSION_NOT_FOUND", "Relación rol-permiso no encontrada", HttpStatus.NOT_FOUND));
        rolPermiso.setEstado(EstadoGeneralEnum.INACTIVO);
        rolPermisoRepository.save(rolPermiso);
        return new GenericResponse("OK", "Permiso revocado correctamente");
    }

    @Transactional
    public ApiClientResponse createApiClient(CreateApiClientRequest request) {
        if (apiClientRepository.existsByClientId(request.clientId())) {
            throw new BusinessException("IAM_CLIENT_EXISTS", "El API client ya existe", HttpStatus.CONFLICT);
        }
        ApiClient client = new ApiClient();
        client.setClientId(request.clientId());
        client.setClientSecretHash(passwordEncoder.encode(request.clientSecret()));
        client.setNombre(request.name());
        client.setServicioOrigen(request.originService());
        client.setTipoCliente(TipoApiClientEnum.valueOf(request.clientType()));
        client.setEstado(EstadoApiClientEnum.ACTIVO);
        client.setFechaCreacion(LocalDateTime.now());
        client.setFechaActualizacion(LocalDateTime.now());
        client.setVersion(0);
        apiClientRepository.save(client);
        return toApiClientResponse(client);
    }

    @Transactional
    public ApiClientResponse assignClientScope(String clientId, AssignClientScopeRequest request) {
        ApiClient client = apiClientRepository.findByClientId(clientId)
                .orElseThrow(() -> new BusinessException("IAM_CLIENT_NOT_FOUND", "API client no encontrado", HttpStatus.NOT_FOUND));
        apiClientScopeRepository.findByApiClientAndScope(client, request.scope()).ifPresentOrElse(scope -> {
            scope.setEstado(EstadoGeneralEnum.ACTIVO);
            scope.setDescripcion(request.description());
            apiClientScopeRepository.save(scope);
        }, () -> {
            ApiClientScope scope = new ApiClientScope();
            scope.setApiClient(client);
            scope.setScope(request.scope());
            scope.setDescripcion(request.description());
            scope.setEstado(EstadoGeneralEnum.ACTIVO);
            scope.setFechaCreacion(LocalDateTime.now());
            apiClientScopeRepository.save(scope);
        });
        return toApiClientResponse(client);
    }

    @Transactional
    public GenericResponse revokeSession(String sessionUuid) {
        SesionUsuario sesion = sesionRepository.findByUuidSesion(sessionUuid)
                .orElseThrow(() -> new BusinessException("IAM_SESSION_NOT_FOUND", "Sesión no encontrada", HttpStatus.NOT_FOUND));
        sesion.revocar("Revocación administrativa");
        sesionRepository.save(sesion);
        return new GenericResponse("OK", "Sesión revocada correctamente");
    }

    private void assignInitialRoles(UsuarioIdentidad usuario, List<String> roleCodes) {
        if (roleCodes == null || roleCodes.isEmpty()) {
            return;
        }
        for (String roleCode : roleCodes.stream().filter(r -> r != null && !r.isBlank()).map(String::trim).distinct().toList()) {
            Rol rol = rolRepository.findByCodigo(roleCode)
                    .orElseThrow(() -> new BusinessException("IAM_ROLE_NOT_FOUND", "Rol no encontrado: " + roleCode, HttpStatus.NOT_FOUND));
            usuarioRolRepository.findByUsuarioAndRolCodigo(usuario, roleCode).ifPresentOrElse(ur -> {
                ur.setEstado(EstadoAsignacionRolEnum.ACTIVO);
                ur.setFechaRevocacion(null);
                usuarioRolRepository.save(ur);
            }, () -> usuarioRolRepository.save(UsuarioRol.crear(usuario, rol, "SYSTEM")));
        }
    }

    private UserDetailResponse toUserDetail(UsuarioIdentidad usuario) {
        return new UserDetailResponse(
                usuario.getUuidUsuario(), usuario.getUsername(), usuario.getEmail(),
                usuario.getTipoActor().getValue(), usuario.getEstado().getValue(),
                usuario.getUuidReferenciaExterna(), usuario.getReferenciaTipo(), usuario.getUltimoLogin(),
                permissionQueryService.rolesActivos(usuario), permissionQueryService.permisosActivos(usuario)
        );
    }

    private UserSummaryResponse toUserSummary(UsuarioIdentidad usuario) {
        return new UserSummaryResponse(
                usuario.getUuidUsuario(), usuario.getUsername(), usuario.getEmail(), usuario.getTelefonoMovil(),
                usuario.getTipoActor().getValue(), usuario.getEstado().getValue(), usuario.getRequiereCambioPassword(),
                usuario.getUuidReferenciaExterna(), usuario.getReferenciaTipo(), usuario.getUltimoLogin(),
                permissionQueryService.rolesActivos(usuario)
        );
    }

    private RoleResponse toRoleResponse(Rol rol) {
        return new RoleResponse(rol.getCodigo(), rol.getNombre(), rol.getDescripcion(), rol.getTipoRol().getValue(), rol.getEstado().getValue());
    }

    private ApiClientResponse toApiClientResponse(ApiClient client) {
        List<String> scopes = apiClientScopeRepository.findByApiClientAndEstado(client, EstadoGeneralEnum.ACTIVO)
                .stream().map(ApiClientScope::getScope).toList();
        return new ApiClientResponse(client.getClientId(), client.getNombre(), client.getServicioOrigen(), client.getTipoCliente().getValue(), client.getEstado().getValue(), scopes);
    }

    private int normalizePage(Integer page) {
        return page == null || page < 0 ? 0 : page;
    }

    private int normalizeSize(Integer size) {
        if (size == null || size <= 0) return DEFAULT_PAGE_SIZE;
        return Math.min(size, MAX_PAGE_SIZE);
    }

    private String normalizeRequiredText(String value, String fieldName) {
        String normalized = normalizeOptionalText(value);
        if (normalized == null) {
            throw new BusinessException("IAM_REQUIRED_FIELD", "El campo " + fieldName + " es obligatorio", HttpStatus.BAD_REQUEST);
        }
        return normalized;
    }

    private String normalizeOptionalText(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isBlank() ? null : trimmed;
    }

    private TipoActorEnum parseActorType(String value) {
        try {
            return TipoActorEnum.valueOf(normalizeRequiredText(value, "actorType").toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new BusinessException("IAM_INVALID_ACTOR_TYPE", "Tipo de actor inválido. Valores permitidos: CLIENTE, EMPLEADO, SERVICIO", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    private TipoRolEnum parseRoleType(String value) {
        try {
            return TipoRolEnum.valueOf(normalizeRequiredText(value, "roleType").toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new BusinessException("IAM_INVALID_ROLE_TYPE", "Tipo de rol inválido. Valores permitidos: INTERNO, CLIENTE, SERVICIO", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    private EstadoGeneralEnum parseGeneralStatus(String value) {
        String normalized = normalizeRequiredText(value, "status").toUpperCase(Locale.ROOT);
        if ("ACTIVE".equals(normalized)) normalized = "ACTIVO";
        if ("INACTIVE".equals(normalized)) normalized = "INACTIVO";
        try {
            return EstadoGeneralEnum.valueOf(normalized);
        } catch (IllegalArgumentException ex) {
            throw new BusinessException("IAM_INVALID_STATUS", "Estado inválido. Valores permitidos: ACTIVO, INACTIVO", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    private EstadoUsuarioIdentidadEnum parseUserStatus(String value, EstadoUsuarioIdentidadEnum defaultValue) {
        if (value == null || value.isBlank()) return defaultValue;
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        normalized = switch (normalized) {
            case "ACTIVE" -> "ACTIVO";
            case "INACTIVE" -> "INACTIVO";
            case "BLOCKED" -> "BLOQUEADO";
            case "PENDING" -> "PENDIENTE";
            case "REVOKED" -> "REVOCADO";
            default -> normalized;
        };
        try {
            return EstadoUsuarioIdentidadEnum.valueOf(normalized);
        } catch (IllegalArgumentException ex) {
            throw new BusinessException("IAM_INVALID_USER_STATUS", "Estado de usuario inválido. Valores permitidos: ACTIVO, INACTIVO, BLOQUEADO, PENDIENTE, REVOCADO", HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }
}
