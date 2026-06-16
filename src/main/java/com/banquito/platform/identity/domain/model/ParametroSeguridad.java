package com.banquito.platform.identity.domain.model;

import com.banquito.platform.identity.domain.enums.EstadoGeneralEnum;
import com.banquito.platform.identity.domain.enums.TipoParametroSeguridadEnum;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Objects;

@Getter
@Setter
@Entity
@Table(name = "PARAMETRO_SEGURIDAD")
public class ParametroSeguridad {
    @Id
    @Column(name = "CODIGO", length = 60, nullable = false)
    private String codigo;

    @Column(name = "NOMBRE", length = 120, nullable = false)
    private String nombre;

    @Column(name = "VALOR_TEXTO", length = 300, nullable = false)
    private String valorTexto;

    @Enumerated(EnumType.STRING)
    @Column(name = "TIPO_DATO", length = 20, nullable = false)
    private TipoParametroSeguridadEnum tipoDato;

    @Column(name = "DESCRIPCION", length = 500)
    private String descripcion;

    @Enumerated(EnumType.STRING)
    @Column(name = "ESTADO", length = 15, nullable = false)
    private EstadoGeneralEnum estado;

    @Column(name = "FECHA_CREACION", nullable = false)
    private LocalDateTime fechaCreacion;

    @Column(name = "FECHA_ACTUALIZACION", nullable = false)
    private LocalDateTime fechaActualizacion;

    @Version
    @Column(name = "VERSION", nullable = false)
    private Integer version;

    public ParametroSeguridad() {}
    public ParametroSeguridad(String codigo) { this.codigo = codigo; }

    public void actualizar(String valorTexto, EstadoGeneralEnum estado) {
        this.valorTexto = valorTexto;
        this.estado = estado;
        this.fechaActualizacion = LocalDateTime.now();
    }

    public boolean estaActivo() {
        return estado == EstadoGeneralEnum.ACTIVO;
    }

    public int valorEntero(int valorDefecto) {
        try { return Integer.parseInt(valorTexto); } catch (Exception e) { return valorDefecto; }
    }

    @Override public boolean equals(Object o) { if (this == o) return true; if (!(o instanceof ParametroSeguridad that)) return false; if (this.codigo == null || that.codigo == null) return false; return Objects.equals(codigo, that.codigo); }
    @Override public int hashCode() { return Objects.hashCode(codigo); }
    @Override public String toString() { return "ParametroSeguridad{" + "codigo='" + codigo + '\'' + ", tipoDato=" + tipoDato + ", estado=" + estado + '}'; }
}
