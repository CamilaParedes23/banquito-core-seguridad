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
            "PASSWORD_RESET_REQUESTED", "INTERNAL_USER_ONBOARDING_COMPLETED", "CUSTOMER_USER_ACTIVATION_REQUESTED");
    private static final String CUSTOMER_ACTIVATION_TEMPLATE = "CUSTOMER_USER_ACTIVATION_EMAIL";
    private static final String INTERNAL_ACTIVATION_TEMPLATE = "INTERNAL_USER_ACTIVATION_EMAIL";
    private static final String PASSWORD_RESET_TEMPLATE = "PASSWORD_RESET_EMAIL";

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
        String eventType = event.getTipoEvento();
        boolean internalOnboarding = "INTERNAL_USER_ONBOARDING_COMPLETED".equals(eventType);
        boolean customerOnboarding = "CUSTOMER_USER_ACTIVATION_REQUESTED".equals(eventType);
        String token = string(payload, internalOnboarding || customerOnboarding ? "activationToken" : "resetToken");
        String username = string(payload, "username");
        String recipientName = string(payload, customerOnboarding ? "recipientName" : "username");
        boolean switchAccess = "true".equalsIgnoreCase(string(payload, "switchAccessEnabled"));

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("sourceEventUuid", event.getUuidEvento());
        request.put("correlationId", event.getUuidCorrelacion());
        request.put("eventType", eventType);
        request.put("originService", "identity-access-service");
        request.put("priority", "ALTA");
        request.put("channelType", "EMAIL");
        request.put("actorUuid", event.getAgregadoId());
        request.put("actorType", internalOnboarding ? "EMPLEADO" : "CLIENTE");
        request.put("recipient", string(payload, "recipient"));
        request.put("recipientName", recipientName.isBlank() ? username : recipientName);
        request.put("templateCode", resolveTemplateCode(internalOnboarding, customerOnboarding));
        request.put("subject", null);
        request.put("body", null);

        Map<String, Object> renderedPayload = new LinkedHashMap<>();
        renderedPayload.put("nombre", recipientName.isBlank() ? username : recipientName);
        renderedPayload.put("username", username);
        renderedPayload.put("usuario", username);
        renderedPayload.put("token", token);
        renderedPayload.put("codigoTemporal", token);
        renderedPayload.put("expiresInMinutes", string(payload, "expiresInMinutes"));
        renderedPayload.put("vigenciaMinutos", string(payload, "expiresInMinutes"));
        if (customerOnboarding) {
            renderedPayload.put("activationUrl", string(payload, "activationUrl"));
            renderedPayload.put("customerType", string(payload, "customerType"));
            renderedPayload.put("switchAccessEnabled", string(payload, "switchAccessEnabled"));
            renderedPayload.put("switchAccessMessage", switchAccess
                    ? "Este usuario también queda habilitado para el portal de pagos masivos una vez activada la cuenta."
                    : "");
        }
        request.put("payload", renderedPayload);
        return request;
    }

    private String resolveTemplateCode(boolean internalOnboarding, boolean customerOnboarding) {
        if (customerOnboarding) {
            return CUSTOMER_ACTIVATION_TEMPLATE;
        }
        return internalOnboarding ? INTERNAL_ACTIVATION_TEMPLATE : PASSWORD_RESET_TEMPLATE;
    }

    private String string(Map<String, Object> payload, String key) {
        Object value = payload.get(key);
        return value == null ? "" : value.toString();
    }
}
