package com.banquito.platform.identity.application.service;

import com.banquito.platform.identity.api.dto.api.SecurityParameterResponse;
import com.banquito.platform.identity.api.dto.api.UpdateSecurityParameterRequest;
import com.banquito.platform.identity.api.dto.internal.AuthenticatedActor;
import com.banquito.platform.identity.domain.enums.EstadoGeneralEnum;
import com.banquito.platform.identity.domain.enums.ResultadoAuditoriaSeguridadEnum;
import com.banquito.platform.identity.domain.enums.TipoParametroSeguridadEnum;
import com.banquito.platform.identity.domain.model.ParametroSeguridad;
import com.banquito.platform.identity.domain.model.UsuarioIdentidad;
import com.banquito.platform.identity.domain.repository.ParametroSeguridadRepository;
import com.banquito.platform.identity.domain.repository.UsuarioIdentidadRepository;
import com.banquito.platform.identity.shared.exception.BusinessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.time.LocalTime;
import java.util.List;
import java.util.Map;

@Service
public class ParametroSeguridadService {
    private static final Map<String, IntRange> INTEGER_RANGES = Map.of(
            "PASSWORD_MIN_LENGTH", new IntRange(8, 128),
            "MAX_FAILED_ATTEMPTS", new IntRange(1, 20),
            "ACCESS_TOKEN_MINUTES", new IntRange(5, 1440),
            "REFRESH_TOKEN_DAYS", new IntRange(1, 90),
            "PASSWORD_RESET_TOKEN_MINUTES", new IntRange(5, 120)
    );

    private final ParametroSeguridadRepository parametroRepository;
    private final UsuarioIdentidadRepository usuarioRepository;
    private final AuditoriaSeguridadService auditoriaService;
    private final ObjectMapper objectMapper;

    public ParametroSeguridadService(ParametroSeguridadRepository parametroRepository,
                                     UsuarioIdentidadRepository usuarioRepository,
                                     AuditoriaSeguridadService auditoriaService,
                                     ObjectMapper objectMapper) {
        this.parametroRepository = parametroRepository;
        this.usuarioRepository = usuarioRepository;
        this.auditoriaService = auditoriaService;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public int getInteger(String code, int defaultValue) {
        return parametroRepository.findById(code)
                .filter(ParametroSeguridad::estaActivo)
                .map(p -> p.valorEntero(defaultValue))
                .orElse(defaultValue);
    }

    @Transactional(readOnly = true)
    public List<SecurityParameterResponse> list() {
        return parametroRepository.findAllByOrderByCodigoAsc().stream().map(this::toResponse).toList();
    }

    @Transactional(readOnly = true)
    public SecurityParameterResponse get(String code) {
        return toResponse(requireParameter(code));
    }

    @Transactional
    public SecurityParameterResponse update(String code,
                                            UpdateSecurityParameterRequest request,
                                            AuthenticatedActor actor,
                                            String ip,
                                            String userAgent) {
        ParametroSeguridad parameter = requireParameter(code);
        String normalizedValue = request.value().trim();
        validateValue(parameter, normalizedValue);
        EstadoGeneralEnum status = request.status() == null || request.status().isBlank()
                ? parameter.getEstado()
                : parseStatus(request.status());
        parameter.actualizar(normalizedValue, status);
        parametroRepository.saveAndFlush(parameter);
        audit(actor, parameter, ip, userAgent);
        return toResponse(parameter);
    }

    private ParametroSeguridad requireParameter(String code) {
        String normalized = code == null ? "" : code.trim().toUpperCase();
        return parametroRepository.findById(normalized)
                .orElseThrow(() -> new BusinessException(
                        "IAM_SECURITY_PARAMETER_NOT_FOUND",
                        "Parámetro de seguridad no encontrado",
                        HttpStatus.NOT_FOUND));
    }

    private void validateValue(ParametroSeguridad parameter, String value) {
        try {
            TipoParametroSeguridadEnum type = parameter.getTipoDato();
            switch (type) {
                case INTEGER -> validateInteger(parameter.getCodigo(), value);
                case DECIMAL -> new BigDecimal(value);
                case BOOLEAN -> {
                    if (!("true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value))) {
                        throw new IllegalArgumentException("boolean");
                    }
                }
                case TIME -> LocalTime.parse(value);
                case JSON -> objectMapper.readTree(value);
                case STRING -> {
                    if (value.isBlank()) throw new IllegalArgumentException("blank");
                }
            }
        } catch (BusinessException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new BusinessException(
                    "IAM_SECURITY_PARAMETER_VALUE_INVALID",
                    "El valor no corresponde al tipo configurado para el parámetro",
                    HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    private void validateInteger(String code, String value) {
        int parsed;
        try {
            parsed = Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            throw new BusinessException(
                    "IAM_SECURITY_PARAMETER_VALUE_INVALID",
                    "El parámetro requiere un valor entero",
                    HttpStatus.UNPROCESSABLE_ENTITY);
        }
        IntRange range = INTEGER_RANGES.get(code);
        if (range != null && (parsed < range.minimum() || parsed > range.maximum())) {
            throw new BusinessException(
                    "IAM_SECURITY_PARAMETER_VALUE_OUT_OF_RANGE",
                    "El valor permitido para " + code + " está entre " + range.minimum() + " y " + range.maximum(),
                    HttpStatus.UNPROCESSABLE_ENTITY);
        }
    }

    private EstadoGeneralEnum parseStatus(String status) {
        try {
            return EstadoGeneralEnum.valueOf(status.trim().toUpperCase());
        } catch (Exception ex) {
            throw new BusinessException(
                    "IAM_SECURITY_PARAMETER_STATUS_INVALID",
                    "Estado de parámetro de seguridad inválido",
                    HttpStatus.BAD_REQUEST);
        }
    }

    private void audit(AuthenticatedActor actor,
                       ParametroSeguridad parameter,
                       String ip,
                       String userAgent) {
        String details = "{\"parameterCode\":\"" + parameter.getCodigo()
                + "\",\"status\":\"" + parameter.getEstado().name() + "\"}";
        UsuarioIdentidad user = actor == null || actor.subject() == null
                ? null : usuarioRepository.findByUuidUsuario(actor.subject()).orElse(null);
        if (user != null) {
            auditoriaService.registrarUsuario(user, "UPDATE_SECURITY_PARAMETER",
                    ResultadoAuditoriaSeguridadEnum.OK, ip, userAgent, details);
        } else {
            auditoriaService.registrarSistema("UPDATE_SECURITY_PARAMETER",
                    ResultadoAuditoriaSeguridadEnum.OK, details);
        }
    }

    private SecurityParameterResponse toResponse(ParametroSeguridad parameter) {
        return new SecurityParameterResponse(
                parameter.getCodigo(),
                parameter.getNombre(),
                parameter.getValorTexto(),
                parameter.getTipoDato().name(),
                parameter.getDescripcion(),
                parameter.getEstado().name(),
                parameter.getFechaActualizacion(),
                parameter.getVersion());
    }

    private record IntRange(int minimum, int maximum) {}
}
