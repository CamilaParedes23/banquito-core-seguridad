-- R9-D: permisos de mínimo privilegio para el ciclo de vida Core-Switch.
INSERT IGNORE INTO PERMISO (CODIGO, NOMBRE, MODULO, ACCION, RECURSO) VALUES
('core.reserve.read', 'Consultar reserva de pago masivo', 'ACCOUNT', 'READ', 'RESERVE'),
('core.reserve.fee', 'Liquidar comisión de pago masivo', 'ACCOUNT', 'EXECUTE', 'RESERVE_FEE'),
('core.reserve.close', 'Cerrar reserva de pago masivo', 'ACCOUNT', 'EXECUTE', 'RESERVE_CLOSE'),
('core.reserve.reverse', 'Reversar reserva de pago masivo', 'ACCOUNT', 'EXECUTE', 'RESERVE_REVERSE');

INSERT IGNORE INTO ROL_PERMISO (ROL_ID, PERMISO_ID)
SELECT r.ID, p.ID
FROM ROL r
JOIN PERMISO p
WHERE r.CODIGO = 'SWITCH_SERVICE'
  AND p.CODIGO IN (
      'core.reserve.read',
      'core.reserve.fee',
      'core.reserve.close',
      'core.reserve.reverse'
  );

INSERT IGNORE INTO API_CLIENT_SCOPE (API_CLIENT_ID, SCOPE)
SELECT c.ID, scopes.SCOPE
FROM API_CLIENT c
JOIN (
    SELECT 'switch-pagos-internos-service' CLIENT_ID, 'core.reserve.read' SCOPE UNION ALL
    SELECT 'switch-pagos-internos-service', 'core.reserve.fee' UNION ALL
    SELECT 'switch-pagos-internos-service', 'core.reserve.close' UNION ALL
    SELECT 'switch-pagos-internos-service', 'core.reserve.reverse'
) scopes ON scopes.CLIENT_ID = c.CLIENT_ID;
