package com.banquito.platform.identity.domain.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "PASSWORD_RECOVERY_TOKEN")
public class PasswordRecoveryToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID", nullable = false)
    private Long id;

    @Column(name = "UUID_TOKEN", length = 36, nullable = false)
    private String uuidToken;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "USUARIO_ID", nullable = false)
    private UsuarioIdentidad usuario;

    @Column(name = "TOKEN_HASH", length = 64, nullable = false)
    private String tokenHash;

    @Column(name = "FECHA_EXPIRACION", nullable = false)
    private LocalDateTime fechaExpiracion;

    @Column(name = "FECHA_USO")
    private LocalDateTime fechaUso;

    @Column(name = "FECHA_CREACION", nullable = false)
    private LocalDateTime fechaCreacion;

    @Column(name = "IP_SOLICITUD", length = 45)
    private String ipSolicitud;

    @Column(name = "USER_AGENT", length = 500)
    private String userAgent;

    @Version
    @Column(name = "VERSION", nullable = false)
    private Integer version;

    public PasswordRecoveryToken() {
    }

    public static PasswordRecoveryToken crear(UsuarioIdentidad usuario,
                                                String tokenHash,
                                                LocalDateTime fechaExpiracion,
                                                String ip,
                                                String userAgent) {
        PasswordRecoveryToken token = new PasswordRecoveryToken();
        token.uuidToken = UUID.randomUUID().toString();
        token.usuario = usuario;
        token.tokenHash = tokenHash;
        token.fechaExpiracion = fechaExpiracion;
        token.fechaCreacion = LocalDateTime.now();
        token.ipSolicitud = ip;
        token.userAgent = userAgent;
        token.version = 0;
        return token;
    }

    public boolean estaVigente(LocalDateTime ahora) {
        return fechaUso == null && fechaExpiracion != null && fechaExpiracion.isAfter(ahora);
    }

    public void marcarUsado(LocalDateTime ahora) {
        this.fechaUso = ahora;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PasswordRecoveryToken that)) return false;
        if (id == null || that.id == null) return false;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(id);
    }
}
