package com.banquito.platform.identity.api.dto.api;

import java.util.List;

public record CustomerUserAccessSummaryResponse(
        String customerUuid,
        List<CustomerUserOnboardingResponse> users
) {}
