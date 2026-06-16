package com.banquito.platform.identity.api.dto.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateSecurityParameterRequest(
        @NotBlank @Size(max = 300) String value,
        @Size(max = 15) String status
) {}
