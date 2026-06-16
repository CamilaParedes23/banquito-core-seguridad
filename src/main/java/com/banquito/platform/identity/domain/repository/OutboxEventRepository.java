package com.banquito.platform.identity.domain.repository;

import com.banquito.platform.identity.domain.enums.EstadoOutboxEventEnum;
import com.banquito.platform.identity.domain.model.OutboxEvent;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;

public interface OutboxEventRepository extends JpaRepository<OutboxEvent, Long> {
    List<OutboxEvent> findByTipoEventoInAndEstadoInAndIntentosLessThanOrderByFechaCreacionAsc(
            Collection<String> eventTypes,
            Collection<EstadoOutboxEventEnum> states,
            Integer maxAttempts,
            Pageable pageable
    );
}
