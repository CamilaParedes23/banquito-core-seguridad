package com.banquito.platform.identity.api.controller;

import com.banquito.platform.identity.api.dto.api.*;
import com.banquito.platform.identity.application.service.AuthenticationService;
import com.banquito.platform.identity.application.service.PasswordManagementService;
import com.banquito.platform.identity.api.dto.internal.AuthenticatedActor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthenticationService authenticationService;
    private final PasswordManagementService passwordManagementService;

    public AuthController(AuthenticationService authenticationService,
                          PasswordManagementService passwordManagementService) {
        this.authenticationService = authenticationService;
        this.passwordManagementService = passwordManagementService;
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        return authenticationService.login(request, ip(httpRequest), httpRequest.getHeader("User-Agent"));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshTokenRequest request, HttpServletRequest httpRequest) {
        return authenticationService.refresh(request, ip(httpRequest), httpRequest.getHeader("User-Agent"));
    }

    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PostMapping("/logout")
    public void logout(@RequestBody(required = false) LogoutRequest request, HttpServletRequest httpRequest) {
        authenticationService.logout(request, ip(httpRequest), httpRequest.getHeader("User-Agent"));
    }

    @PostMapping("/introspect")
    public TokenIntrospectionResponse introspect(@Valid @RequestBody TokenIntrospectionRequest request) {
        return authenticationService.introspect(request);
    }

    @PostMapping("/client-token")
    public TokenResponse clientToken(@Valid @RequestBody ClientTokenRequest request, HttpServletRequest httpRequest) {
        return authenticationService.clientToken(request, ip(httpRequest), httpRequest.getHeader("User-Agent"));
    }


    @PostMapping("/change-password")
    public GenericResponse changePassword(@Valid @RequestBody ChangePasswordRequest request,
                                          Authentication authentication,
                                          HttpServletRequest httpRequest) {
        AuthenticatedActor actor = authentication == null ? null : (AuthenticatedActor) authentication.getPrincipal();
        return passwordManagementService.changePassword(actor, request, ip(httpRequest), httpRequest.getHeader("User-Agent"));
    }

    @PostMapping("/forgot-password")
    public GenericResponse forgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
                                          HttpServletRequest httpRequest) {
        return passwordManagementService.forgotPassword(request, ip(httpRequest), httpRequest.getHeader("User-Agent"));
    }

    @PostMapping("/reset-password")
    public GenericResponse resetPassword(@Valid @RequestBody ResetPasswordRequest request,
                                         HttpServletRequest httpRequest) {
        return passwordManagementService.resetPassword(request, ip(httpRequest), httpRequest.getHeader("User-Agent"));
    }

    @GetMapping("/me")
    public AuthenticatedSessionResponse me(Authentication authentication) {
        AuthenticatedActor actor = authentication == null ? null : (AuthenticatedActor) authentication.getPrincipal();
        return authenticationService.me(actor);
    }

    private String ip(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
