package com.banquito.platform.identity.domain.repository;

import com.banquito.platform.identity.domain.model.ParametroSeguridad;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ParametroSeguridadRepository extends JpaRepository<ParametroSeguridad, String> {
    List<ParametroSeguridad> findAllByOrderByCodigoAsc();
}

