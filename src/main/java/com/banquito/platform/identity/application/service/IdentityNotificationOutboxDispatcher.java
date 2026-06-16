package com.banquito.platform.identity.application.service;

import com.banquito.platform.identity.domain.model.OutboxEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class IdentityNotificationOutboxDispatcher {
    private static final Logger log = LoggerFactory.getLogger(IdentityNotificationOutboxDispatcher.class);
    private static final List<String> SUPPORTED_EVENTS = List.of(
            "PASSWORD_RESET_REQUESTED", "INTERNAL_USER_ONBOARDING_COMPLETED");

    private final IdentityOutboxService outboxService;
    private final RestClient notificationClient;
    private final ObjectMapper objectMapper;
    private final String internalServiceKey;
    private final boolean enabled;
    private final int batchSize;
    private final int maxAttempts;

    public IdentityNotificationOutboxDispatcher(
            IdentityOutboxService outboxService,
            RestClient.Builder restClientBuilder,
            ObjectMapper objectMapper,
            @Value("${banquito.integrations.notification.base-url:http://localhost:8087}") String notificationBaseUrl,
            @Value("${banquito.internal.service-key:banquito-internal-development-key}") String internalServiceKey,
            @Value("${banquito.integration.outbox.enabled:true}") boolean enabled,
            @Value("${banquito.integration.outbox.batch-size:20}") int batchSize,
            @Value("${banquito.integration.outbox.max-attempts:5}") int maxAttempts) {
        this.outboxService = outboxService;
        this.notificationClient = restClientBuilder.baseUrl(notificationBaseUrl).build();
        this.objectMapper = objectMapper;
        this.internalServiceKey = internalServiceKey;
        this.enabled = enabled;
        this.batchSize = batchSize;
        this.maxAttempts = maxAttempts;
    }

    @Scheduled(fixedDelayString = "${banquito.integration.outbox.fixed-delay-ms:5000}")
    public void dispatch() {
        if (!enabled) return;
        for (OutboxEvent event : outboxService.findDispatchable(SUPPORTED_EVENTS, maxAttempts, batchSize)) {
            try {
                Map<String, Object> payload = objectMapper.readValue(
                        event.getPayloadJson(), new TypeReference<Map<String, Object>>() {});
                notificationClient.post()
                        .uri("/internal/v1/notifications/requests")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Internal-Service-Key", internalServiceKey)
                        .body(toNotificationRequest(event, payload))
                        .retrieve()
                        .toBodilessEntity();
                outboxService.markPublished(event.getId());
            } catch (Exception ex) {
                log.warn("No fue posible despachar evento Identity {} tipo {}: {}",
                        event.getUuidEvento(), event.getTipoEvento(), ex.getMessage());
                outboxService.markError(event.getId(), ex.getMessage(), maxAttempts);
            }
        }
    }

    private Map<String, Object> toNotificationRequest(OutboxEvent event, Map<String, Object> payload) {
        boolean onboarding = "INTERNAL_USER_ONBOARDING_COMPLETED".equals(event.getTipoEvento());
        String token = string(payload, onboarding ? "activationToken" : "resetToken");
        String username = string(payload, "username");
        String subject = onboarding
                ? "Active su acceso interno a Banco BanQuito"
                : "Recuperación de contraseña de Banco BanQuito";
        String body = onboarding
                ? "Hola " + username + ", use el siguiente token de un solo uso para definir su contraseña: " + token
                : "Hola " + username + ", use el siguiente token de un solo uso para restablecer su contraseña: " + token;

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("sourceEventUuid", event.getUuidEvento());
        request.put("correlationId", event.getUuidCorrelacion());
        request.put("eventType", event.getTipoEvento());
        request.put("originService", "identity-access-service");
        request.put("priority", "ALTA");
        request.put("channelType", "EMAIL");
        request.put("actorUuid", event.getAgregadoId());
        request.put("actorType", "EMPLEADO");
        request.put("recipient", string(payload, "recipient"));
        request.put("recipientName", username);
        request.put("subject", subject);
        request.put("body", body);
        request.put("payload", Map.of(
                "username", username,
                "token", token,
                "expiresInMinutes", string(payload, "expiresInMinutes")
        ));
        return request;
    }

    private String string(Map<String, Object> payload, String key) {
        Object value = payload.get(key);
        return value == null ? "" : value.toString();
    }
}
