package com.banquito.platform.identity.api.controller;

import com.banquito.platform.identity.api.dto.api.CreateUserRequest;
import com.banquito.platform.identity.api.dto.api.RoleResponse;
import com.banquito.platform.identity.api.dto.api.UserDetailResponse;
import com.banquito.platform.identity.api.dto.api.UserListResponse;
import com.banquito.platform.identity.application.service.IamManagementService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/auth")
public class IamAuthAliasController {
    private final IamManagementService iamService;

    public IamAuthAliasController(IamManagementService iamService) {
        this.iamService = iamService;
    }

    @GetMapping("/roles")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public List<RoleResponse> listRoles(@RequestParam(required = false) String status) {
        return iamService.listRoles(status);
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

    @GetMapping("/users/by-username/{username}")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public UserDetailResponse getUserByUsername(@PathVariable String username) {
        return iamService.getUserByUsername(username);
    }

    @PostMapping("/users")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public UserDetailResponse createUser(@Valid @RequestBody CreateUserRequest request) {
        return iamService.createUser(request);
    }
}
