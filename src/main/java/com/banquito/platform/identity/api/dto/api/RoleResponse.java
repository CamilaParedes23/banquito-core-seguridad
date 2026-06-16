package com.banquito.platform.identity.api.dto.api;

public record RoleResponse(
        String code,
        String name,
        String description,
        String roleType,
        String status
) {}
