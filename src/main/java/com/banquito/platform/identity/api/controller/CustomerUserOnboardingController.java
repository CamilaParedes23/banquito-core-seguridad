package com.banquito.platform.identity.api.controller;

import com.banquito.platform.identity.api.dto.api.CustomerUserAccessSummaryResponse;
import com.banquito.platform.identity.api.dto.api.CustomerUserOnboardingRequest;
import com.banquito.platform.identity.api.dto.api.CustomerUserOnboardingResponse;
import com.banquito.platform.identity.application.service.CustomerUserOnboardingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/iam/customer-users")
public class CustomerUserOnboardingController {
    private final CustomerUserOnboardingService service;

    public CustomerUserOnboardingController(CustomerUserOnboardingService service) {
        this.service = service;
    }

    @PostMapping("/onboarding")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public CustomerUserOnboardingResponse onboard(@Valid @RequestBody CustomerUserOnboardingRequest request,
                                                  HttpServletRequest httpRequest) {
        return service.onboard(request, clientIp(httpRequest), httpRequest.getHeader("User-Agent"));
    }

    @GetMapping("/by-customer/{customerUuid}")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public CustomerUserAccessSummaryResponse byCustomer(@PathVariable String customerUuid) {
        return service.findByCustomer(customerUuid);
    }

    @PostMapping("/{userUuid}/resend-activation")
    @PreAuthorize("hasAuthority('SCOPE_auth.user.manage') or hasRole('ADMIN_SEGURIDAD')")
    public CustomerUserOnboardingResponse resendActivation(@PathVariable String userUuid, HttpServletRequest httpRequest) {
        return service.resendActivation(userUuid, clientIp(httpRequest), httpRequest.getHeader("User-Agent"));
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded == null || forwarded.isBlank() ? request.getRemoteAddr() : forwarded.split(",")[0].trim();
    }
}
