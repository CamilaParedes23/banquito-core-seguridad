package com.banquito.platform.identity.domain.repository;

import com.banquito.platform.identity.domain.model.InternalUserOnboardingRecord;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface InternalUserOnboardingRepository extends JpaRepository<InternalUserOnboardingRecord, Long> {
    Optional<InternalUserOnboardingRecord> findByIdempotencyKey(String idempotencyKey);

    @Modifying
    @Query(value = """
            INSERT IGNORE INTO INTERNAL_USER_ONBOARDING
              (IDEMPOTENCY_KEY, PAYLOAD_HASH, ESTADO, FECHA_CREACION, FECHA_ACTUALIZACION, VERSION)
            VALUES
              (:idempotencyKey, :payloadHash, 'EN_PROCESO', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0)
            """, nativeQuery = true)
    int insertIfAbsent(@Param("idempotencyKey") String idempotencyKey,
                       @Param("payloadHash") String payloadHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select record from InternalUserOnboardingRecord record where record.idempotencyKey = :idempotencyKey")
    Optional<InternalUserOnboardingRecord> findForUpdate(@Param("idempotencyKey") String idempotencyKey);
}
