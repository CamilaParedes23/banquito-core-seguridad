package com.banquito.platform.identity.api.dto.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotBlank(message = "La contraseña actual es obligatoria") String currentPassword,
        @NotBlank(message = "La nueva contraseña es obligatoria")
        @Size(max = 128, message = "La nueva contraseña no puede superar 128 caracteres") String newPassword
) {}
