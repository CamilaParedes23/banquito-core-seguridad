package com.banquito.platform.identity.api.controller;

import com.banquito.platform.identity.api.dto.api.InternalUserOnboardingRequest;
import com.banquito.platform.identity.api.dto.api.InternalUserOnboardingResponse;
import com.banquito.platform.identity.application.service.InternalUserOnboardingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/onboarding")
public class InternalUserOnboardingController {
    private final InternalUserOnboardingService service;

    public InternalUserOnboardingController(InternalUserOnboardingService service) {
        this.service = service;
    }

    @PostMapping("/internal-users")
    @PreAuthorize("hasRole('ADMIN_SEGURIDAD')")
    public ResponseEntity<InternalUserOnboardingResponse> onboard(
            @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody InternalUserOnboardingRequest request,
            HttpServletRequest httpRequest) {
        InternalUserOnboardingService.ExecutionResult result = service.onboard(
                idempotencyKey, request, httpRequest.getHeader(HttpHeaders.AUTHORIZATION),
                ip(httpRequest), httpRequest.getHeader("User-Agent"));
        return ResponseEntity.status(result.replayed() ? HttpStatus.OK : HttpStatus.CREATED)
                .header("Idempotency-Replayed", Boolean.toString(result.replayed()))
                .body(result.response());
    }

    private String ip(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded == null || forwarded.isBlank() ? request.getRemoteAddr() : forwarded.split(",")[0].trim();
    }
}
