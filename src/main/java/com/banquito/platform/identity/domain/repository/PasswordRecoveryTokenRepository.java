package com.banquito.platform.identity.domain.repository;

import com.banquito.platform.identity.domain.model.PasswordRecoveryToken;
import com.banquito.platform.identity.domain.model.UsuarioIdentidad;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PasswordRecoveryTokenRepository extends JpaRepository<PasswordRecoveryToken, Long> {
    Optional<PasswordRecoveryToken> findByTokenHash(String tokenHash);
    List<PasswordRecoveryToken> findByUsuarioAndFechaUsoIsNull(UsuarioIdentidad usuario);
}
