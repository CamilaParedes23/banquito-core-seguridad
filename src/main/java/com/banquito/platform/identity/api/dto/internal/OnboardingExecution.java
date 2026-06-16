package com.banquito.platform.identity.api.dto.internal;

import com.banquito.platform.identity.api.dto.api.InternalUserOnboardingResponse;

public record OnboardingExecution(
        boolean replayed,
        String identityUuid,
        InternalUserOnboardingResponse response
) {}
