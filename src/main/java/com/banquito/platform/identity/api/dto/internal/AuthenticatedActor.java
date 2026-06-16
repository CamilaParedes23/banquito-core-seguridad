package com.banquito.platform.identity.api.dto.internal;

import java.util.List;

public record AuthenticatedActor(
        String subject,
        String username,
        String actorType,
        String clientId,
        List<String> roles,
        List<String> scopes,
        String referenceUuid,
        String referenceType,
        String customerUuid
) {}
