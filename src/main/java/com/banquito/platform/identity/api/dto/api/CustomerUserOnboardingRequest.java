package com.banquito.platform.identity.api.dto.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CustomerUserOnboardingRequest(
        @NotBlank String customerUuid,
        @NotNull String customerType,
        @NotBlank String identification,
        @NotBlank @Size(max = 180) String displayName,
        @Email @NotBlank String email,
        @Pattern(regexp = "^$|^\\+?[0-9]{7,15}$", message = "mobilePhone debe contener entre 7 y 15 dígitos, opcionalmente precedido por +")
        String mobilePhone,
        Boolean massPaymentsEnabled,
        Boolean switchAccessEnabled,
        String username
) {}
