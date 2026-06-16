package com.banquito.platform.identity.api.controller;

import com.banquito.platform.identity.api.dto.api.*;
import com.banquito.platform.identity.application.service.IamManagementService;
import com.banquito.platform.identity.application.service.ParametroSeguridadService;
import com.banquito.platform.identity.api.dto.internal.AuthenticatedActor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/iam")
public class IamController {
    private final IamManagementService iamService;
    private final ParametroSeguridadService parametroSeguridadService;

    public IamController(IamManagementService iamService,
                         ParametroSeguridadService parametroSeguridadService) {
        this.iamService = iamService;
        this.parametroSeguridadService = parametroSeguridadService;
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public UserListResponse listUsers(@RequestParam(required = false) String actorType,
                                      @RequestParam(required = false) String status,
                                      @RequestParam(required = false) String username,
                                      @RequestParam(required = false) String search,
                                      @RequestParam(required = false) Integer page,
                                      @RequestParam(required = false) Integer size) {
        return iamService.listUsers(actorType, status, username, search, page, size);
    }

    @PostMapping("/users")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public UserDetailResponse createUser(@Valid @RequestBody CreateUserRequest request) {
        return iamService.createUser(request);
    }

    @GetMapping("/users/{userUuid}")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or authentication.name == #userUuid")
    public UserDetailResponse getUser(@PathVariable String userUuid) {
        return iamService.getUser(userUuid);
    }

    @GetMapping("/users/by-username/{username}")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public UserDetailResponse getUserByUsername(@PathVariable String username) {
        return iamService.getUserByUsername(username);
    }

    @PatchMapping("/users/{userUuid}/status")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public UserDetailResponse changeUserStatus(@PathVariable String userUuid, @Valid @RequestBody ChangeUserStatusRequest request) {
        return iamService.changeUserStatus(userUuid, request);
    }

    @PostMapping("/users/{userUuid}/roles")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public GenericResponse assignRole(@PathVariable String userUuid, @Valid @RequestBody AssignRoleRequest request) {
        return iamService.assignRole(userUuid, request);
    }

    @DeleteMapping("/users/{userUuid}/roles/{roleCode}")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public GenericResponse revokeRole(@PathVariable String userUuid, @PathVariable String roleCode) {
        return iamService.revokeRole(userUuid, roleCode);
    }

    @GetMapping("/roles")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public List<RoleResponse> listRoles(@RequestParam(required = false) String status) {
        return iamService.listRoles(status);
    }

    @PostMapping("/roles")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public GenericResponse createRole(@Valid @RequestBody CreateRoleRequest request) {
        return iamService.createRole(request);
    }

    @PostMapping("/permissions")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public GenericResponse createPermission(@Valid @RequestBody CreatePermissionRequest request) {
        return iamService.createPermission(request);
    }

    @PostMapping("/roles/{roleCode}/permissions")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public GenericResponse assignPermission(@PathVariable String roleCode, @Valid @RequestBody AssignPermissionRequest request) {
        return iamService.assignPermission(roleCode, request);
    }

    @DeleteMapping("/roles/{roleCode}/permissions/{permissionCode}")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public GenericResponse revokePermission(@PathVariable String roleCode, @PathVariable String permissionCode) {
        return iamService.revokePermission(roleCode, permissionCode);
    }

    @PostMapping("/api-clients")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public ApiClientResponse createApiClient(@Valid @RequestBody CreateApiClientRequest request) {
        return iamService.createApiClient(request);
    }

    @PostMapping("/api-clients/{clientId}/scopes")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public ApiClientResponse assignClientScope(@PathVariable String clientId, @Valid @RequestBody AssignClientScopeRequest request) {
        return iamService.assignClientScope(clientId, request);
    }

    @GetMapping("/security-parameters")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public List<SecurityParameterResponse> listSecurityParameters() {
        return parametroSeguridadService.list();
    }

    @GetMapping("/security-parameters/{code}")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public SecurityParameterResponse getSecurityParameter(@PathVariable String code) {
        return parametroSeguridadService.get(code);
    }

    @PatchMapping("/security-parameters/{code}")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public SecurityParameterResponse updateSecurityParameter(
            @PathVariable String code,
            @Valid @RequestBody UpdateSecurityParameterRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        AuthenticatedActor actor = authentication == null ? null : (AuthenticatedActor) authentication.getPrincipal();
        return parametroSeguridadService.update(code, request, actor, clientIp(httpRequest), httpRequest.getHeader("User-Agent"));
    }

    @PostMapping("/sessions/{sessionUuid}/revoke")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public GenericResponse revokeSession(@PathVariable String sessionUuid) {
        return iamService.revokeSession(sessionUuid);
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded == null || forwarded.isBlank()
                ? request.getRemoteAddr()
                : forwarded.split(",")[0].trim();
    }
}
