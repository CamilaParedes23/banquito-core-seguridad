package com.banquito.platform.identity.shared.exception;

import com.banquito.platform.identity.api.dto.api.ErrorResponse;
import com.banquito.platform.identity.shared.tracing.CorrelationIdHolder;
import jakarta.validation.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.time.LocalDateTime;
import java.util.List;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ErrorResponse> handleBusiness(BusinessException ex) {
        return ResponseEntity.status(ex.getStatus()).body(new ErrorResponse(
                LocalDateTime.now(), CorrelationIdHolder.get(), ex.getCode(), ex.getMessage(), List.of()
        ));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        List<String> details = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> e.getField() + ": " + e.getDefaultMessage()).toList();
        return ResponseEntity.badRequest().body(new ErrorResponse(
                LocalDateTime.now(), CorrelationIdHolder.get(), "VALIDATION_ERROR", "La solicitud contiene datos inválidos", details
        ));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraint(ConstraintViolationException ex) {
        return ResponseEntity.badRequest().body(new ErrorResponse(
                LocalDateTime.now(), CorrelationIdHolder.get(), "VALIDATION_ERROR", "La solicitud contiene parámetros inválidos", List.of(ex.getMessage())
        ));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest().body(new ErrorResponse(
                LocalDateTime.now(), CorrelationIdHolder.get(), "REQUEST_BODY_INVALID", "El cuerpo de la solicitud no tiene un JSON válido o no cumple el formato esperado", List.of()
        ));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrity(DataIntegrityViolationException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse(
                LocalDateTime.now(), CorrelationIdHolder.get(), "DATA_INTEGRITY_VIOLATION", "La operación viola una restricción de integridad o unicidad de datos", List.of()
        ));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResource(NoResourceFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse(
                LocalDateTime.now(), CorrelationIdHolder.get(), "RESOURCE_NOT_FOUND", "El recurso solicitado no existe", List.of(ex.getResourcePath())
        ));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(new ErrorResponse(
                LocalDateTime.now(), CorrelationIdHolder.get(), "INVALID_ARGUMENT", ex.getMessage(), List.of()
        ));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorResponse(
                LocalDateTime.now(),
                CorrelationIdHolder.get(),
                "SECURITY_ACCESS_DENIED",
                "Acceso denegado. El token no posee permisos para este recurso.",
                List.of()
        ));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ErrorResponse(
                LocalDateTime.now(), CorrelationIdHolder.get(), "INTERNAL_ERROR", "Error interno no controlado", List.of(ex.getClass().getSimpleName())
        ));
    }
}
