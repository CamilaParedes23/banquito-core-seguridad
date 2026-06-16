package com.banquito.platform.identity.api.dto.api;

import java.time.LocalDateTime;
import java.util.List;

public record UserSummaryResponse(
        String userUuid,
        String username,
        String email,
        String mobilePhone,
        String actorType,
        String status,
        Boolean requiresPasswordChange,
        String externalReferenceUuid,
        String referenceType,
        LocalDateTime lastLogin,
        List<String> roles
) {}
