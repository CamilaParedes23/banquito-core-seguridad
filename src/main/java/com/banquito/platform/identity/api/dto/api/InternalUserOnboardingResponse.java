package com.banquito.platform.identity.api.dto.api;

import java.util.List;

public record InternalUserOnboardingResponse(
        String identityUuid,
        String coreUserUuid,
        String username,
        String email,
        String branchCode,
        String fullName,
        String position,
        List<String> roles,
        String status,
        boolean activationIssued
) {}
