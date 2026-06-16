package com.banquito.platform.identity.api.dto.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ForgotPasswordRequest(
        @NotBlank(message = "El usuario o correo es obligatorio")
        @Size(max = 160, message = "El usuario o correo no puede superar 160 caracteres") String usernameOrEmail
) {}
