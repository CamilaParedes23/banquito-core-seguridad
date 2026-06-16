package com.banquito.platform.identity.api.dto.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

public record CreateUserRequest(
        @NotBlank String username,
        @Email String email,
        @Pattern(regexp = "^\\+?[0-9]{7,15}$", message = "telefonoMovil debe contener entre 7 y 15 dígitos, opcionalmente precedido por +")
        String telefonoMovil,
        @NotBlank @Size(min = 8, max = 128, message = "password debe tener entre 8 y 128 caracteres")
        String password,
        @NotNull String actorType,
        String externalReferenceUuid,
        String referenceType,
        Boolean requirePasswordChange,
        List<String> roleCodes,
        String status
) {}
