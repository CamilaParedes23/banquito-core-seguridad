package com.banquito.platform.identity.api.dto.api;

import java.util.List;

public record UserListResponse(
        long total,
        int page,
        int size,
        int totalPages,
        List<UserSummaryResponse> users
) {}
