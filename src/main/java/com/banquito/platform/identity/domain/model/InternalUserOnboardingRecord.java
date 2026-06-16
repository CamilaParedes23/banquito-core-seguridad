package com.banquito.platform.identity.domain.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Objects;

@Getter
@Setter
@Entity
@Table(name = "INTERNAL_USER_ONBOARDING")
public class InternalUserOnboardingRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID", nullable = false)
    private Long id;

    @Column(name = "IDEMPOTENCY_KEY", length = 80, nullable = false)
    private String idempotencyKey;

    @Column(name = "PAYLOAD_HASH", length = 64, nullable = false)
    private String payloadHash;

    @Column(name = "ESTADO", length = 20, nullable = false)
    private String estado;

    @Column(name = "UUID_IDENTIDAD", length = 36)
    private String uuidIdentidad;

    @Column(name = "UUID_USUARIO_CORE", length = 36)
    private String uuidUsuarioCore;

    @Column(name = "RESPUESTA_JSON", columnDefinition = "json")
    private String respuestaJson;

    @Column(name = "ERROR_ULTIMO", length = 1000)
    private String errorUltimo;

    @Column(name = "FECHA_CREACION", nullable = false)
    private LocalDateTime fechaCreacion;

    @Column(name = "FECHA_ACTUALIZACION", nullable = false)
    private LocalDateTime fechaActualizacion;

    @Version
    @Column(name = "VERSION", nullable = false)
    private Integer version;

    public InternalUserOnboardingRecord() {}

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        if (fechaCreacion == null) fechaCreacion = now;
        if (fechaActualizacion == null) fechaActualizacion = now;
        if (version == null) version = 0;
    }

    @PreUpdate
    void preUpdate() {
        fechaActualizacion = LocalDateTime.now();
    }

    @Override public boolean equals(Object o) { if (this == o) return true; if (!(o instanceof InternalUserOnboardingRecord that)) return false; if (id == null || that.id == null) return false; return Objects.equals(id, that.id); }
    @Override public int hashCode() { return Objects.hashCode(id); }
}
