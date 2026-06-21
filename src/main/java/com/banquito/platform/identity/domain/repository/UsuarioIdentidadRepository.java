package com.banquito.platform.identity.domain.repository;

import com.banquito.platform.identity.domain.enums.EstadoUsuarioIdentidadEnum;
import com.banquito.platform.identity.domain.model.UsuarioIdentidad;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.List;
import java.util.Optional;

public interface UsuarioIdentidadRepository extends JpaRepository<UsuarioIdentidad, Long>, JpaSpecificationExecutor<UsuarioIdentidad> {
    Optional<UsuarioIdentidad> findByUsername(String username);
    Optional<UsuarioIdentidad> findByUsernameIgnoreCase(String username);
    Optional<UsuarioIdentidad> findByEmailIgnoreCase(String email);
    Optional<UsuarioIdentidad> findByUuidUsuario(String uuidUsuario);
    boolean existsByUsername(String username);
    boolean existsByUsernameIgnoreCase(String username);
    boolean existsByEmail(String email);
    boolean existsByEmailIgnoreCase(String email);
    long countByEstado(EstadoUsuarioIdentidadEnum estado);
    List<UsuarioIdentidad> findByUuidReferenciaExternaAndReferenciaTipo(String uuidReferenciaExterna, String referenciaTipo);
}
