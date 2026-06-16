package com.banquito.platform.identity.application.service;

import com.banquito.platform.identity.api.dto.api.InternalUserOnboardingRequest;
import com.banquito.platform.identity.api.dto.api.InternalUserOnboardingResponse;
import com.banquito.platform.identity.api.dto.internal.OnboardingExecution;
import com.banquito.platform.identity.domain.model.InternalUserOnboardingRecord;
import com.banquito.platform.identity.domain.repository.InternalUserOnboardingRepository;
import com.banquito.platform.identity.shared.exception.BusinessException;
import com.banquito.platform.identity.shared.util.HashUtil;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class InternalUserOnboardingIdempotencyService {
    private final InternalUserOnboardingRepository repository;
    private final ObjectMapper objectMapper;

    public InternalUserOnboardingIdempotencyService(InternalUserOnboardingRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public OnboardingExecution begin(String key, InternalUserOnboardingRequest request) {
        String normalizedKey = normalizeKey(key);
        String hash = hash(request);
        int inserted = repository.insertIfAbsent(normalizedKey, hash);
        InternalUserOnboardingRecord existing = repository.findForUpdate(normalizedKey)
                .orElseThrow(() -> new IllegalStateException("No fue posible crear el registro de idempotencia del onboarding"));

        if (inserted == 1) {
            return new OnboardingExecution(false, null, null);
        }
        if (!existing.getPayloadHash().equals(hash)) {
            throw new BusinessException("IDEMPOTENCY_PAYLOAD_CONFLICT",
                    "La misma Idempotency-Key fue utilizada con un payload diferente", HttpStatus.CONFLICT);
        }
        if ("COMPLETADA".equals(existing.getEstado()) && existing.getRespuestaJson() != null) {
            return new OnboardingExecution(true, existing.getUuidIdentidad(), read(existing.getRespuestaJson()));
        }
        if ("EN_PROCESO".equals(existing.getEstado())
                && existing.getFechaActualizacion().isAfter(LocalDateTime.now().minusMinutes(5))) {
            throw new BusinessException("IDEMPOTENCY_OPERATION_IN_PROGRESS",
                    "El onboarding con esta llave todavía está en proceso", HttpStatus.CONFLICT);
        }
        existing.setEstado("EN_PROCESO");
        existing.setErrorUltimo(null);
        repository.saveAndFlush(existing);
        return new OnboardingExecution(false, existing.getUuidIdentidad(), null);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void linkIdentity(String key, String identityUuid) {
        InternalUserOnboardingRecord record = required(key);
        record.setUuidIdentidad(identityUuid);
        repository.saveAndFlush(record);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void complete(String key, InternalUserOnboardingResponse response) {
        InternalUserOnboardingRecord record = required(key);
        record.setEstado("COMPLETADA");
        record.setUuidIdentidad(response.identityUuid());
        record.setUuidUsuarioCore(response.coreUserUuid());
        record.setRespuestaJson(write(response));
        record.setErrorUltimo(null);
        repository.saveAndFlush(record);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void fail(String key, Exception exception) {
        repository.findByIdempotencyKey(normalizeKey(key)).ifPresent(record -> {
            record.setEstado("FALLIDA");
            String message = exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage();
            record.setErrorUltimo(message.substring(0, Math.min(message.length(), 1000)));
            repository.saveAndFlush(record);
        });
    }

    private String normalizeKey(String key) {
        if (key == null || key.isBlank()) {
            throw new BusinessException("IDEMPOTENCY_KEY_REQUIRED",
                    "Idempotency-Key es obligatorio y debe ser un UUID válido", HttpStatus.BAD_REQUEST);
        }
        String normalized = key.trim();
        try {
            return UUID.fromString(normalized).toString();
        } catch (IllegalArgumentException ex) {
            throw new BusinessException("IDEMPOTENCY_KEY_INVALID",
                    "Idempotency-Key debe ser un UUID válido", HttpStatus.BAD_REQUEST);
        }
    }

    private InternalUserOnboardingRecord required(String key) {
        return repository.findByIdempotencyKey(normalizeKey(key))
                .orElseThrow(() -> new IllegalStateException("No existe el registro de idempotencia del onboarding"));
    }

    private String hash(InternalUserOnboardingRequest request) {
        try {
            return HashUtil.sha256(objectMapper.writeValueAsString(request));
        } catch (Exception ex) {
            throw new IllegalStateException("No fue posible calcular el hash del onboarding", ex);
        }
    }

    private String write(InternalUserOnboardingResponse response) {
        try { return objectMapper.writeValueAsString(response); }
        catch (Exception ex) { throw new IllegalStateException("No fue posible persistir la respuesta del onboarding", ex); }
    }

    private InternalUserOnboardingResponse read(String json) {
        try { return objectMapper.readValue(json, InternalUserOnboardingResponse.class); }
        catch (Exception ex) { throw new IllegalStateException("No fue posible recuperar la respuesta idempotente", ex); }
    }
}
