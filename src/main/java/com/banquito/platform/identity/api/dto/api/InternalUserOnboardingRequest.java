package com.banquito.platform.identity.api.dto.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

public record InternalUserOnboardingRequest(
        @NotBlank @Size(max = 80) String username,
        @NotBlank @Email @Size(max = 160) String email,
        @Pattern(regexp = "^\\+?[0-9]{7,15}$", message = "mobilePhone debe contener entre 7 y 15 dígitos, opcionalmente precedido por +")
        String mobilePhone,
        @NotEmpty List<@NotBlank String> roleCodes,
        String branchCode,
        @NotBlank @Size(max = 160) String fullName,
        @Size(max = 100) String position
) {}
