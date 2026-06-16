package com.banquito.platform.identity.api.dto.api;

import java.time.LocalDateTime;

public record SecurityParameterResponse(
        String code,
        String name,
        String value,
        String dataType,
        String description,
        String status,
        LocalDateTime updatedAt,
        Integer version
) {}
