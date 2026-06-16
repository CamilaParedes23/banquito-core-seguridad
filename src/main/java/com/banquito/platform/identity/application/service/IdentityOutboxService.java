package com.banquito.platform.identity.application.service;

import com.banquito.platform.identity.domain.enums.EstadoOutboxEventEnum;
import com.banquito.platform.identity.domain.model.OutboxEvent;
import com.banquito.platform.identity.domain.repository.OutboxEventRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class IdentityOutboxService {
    private final OutboxEventRepository repository;

    public IdentityOutboxService(OutboxEventRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public List<OutboxEvent> findDispatchable(List<String> eventTypes, int maxAttempts, int batchSize) {
        return repository.findByTipoEventoInAndEstadoInAndIntentosLessThanOrderByFechaCreacionAsc(
                eventTypes,
                List.of(EstadoOutboxEventEnum.PENDIENTE, EstadoOutboxEventEnum.ERROR),
                maxAttempts,
                PageRequest.of(0, Math.max(1, batchSize)));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markPublished(Long id) {
        repository.findById(id).ifPresent(event -> {
            event.setEstado(EstadoOutboxEventEnum.PUBLICADO);
            event.setFechaPublicacion(LocalDateTime.now());
            event.setErrorUltimo(null);
            repository.saveAndFlush(event);
        });
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markError(Long id, String message, int maxAttempts) {
        repository.findById(id).ifPresent(event -> {
            int attempts = event.getIntentos() == null ? 1 : event.getIntentos() + 1;
            event.setIntentos(attempts);
            event.setEstado(attempts >= maxAttempts ? EstadoOutboxEventEnum.DESCARTADO : EstadoOutboxEventEnum.ERROR);
            event.setErrorUltimo(truncate(message));
            repository.saveAndFlush(event);
        });
    }

    private String truncate(String value) {
        if (value == null) return null;
        return value.length() <= 1000 ? value : value.substring(0, 1000);
    }
}
