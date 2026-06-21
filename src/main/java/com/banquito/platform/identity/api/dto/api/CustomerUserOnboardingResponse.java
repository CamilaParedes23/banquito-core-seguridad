package com.banquito.platform.identity.api.dto.api;

import java.util.List;

public record CustomerUserOnboardingResponse(
        String userUuid,
        String username,
        String email,
        String customerUuid,
        String customerType,
        String status,
        List<String> roles,
        boolean activationIssued,
        String message
) {}
