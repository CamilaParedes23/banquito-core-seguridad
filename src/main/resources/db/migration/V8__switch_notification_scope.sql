-- R9-I.1: scope técnico para que Reporting/Switch solicite notificaciones sin rol administrativo.
INSERT IGNORE INTO PERMISO (CODIGO, NOMBRE, MODULO, ACCION, RECURSO) VALUES
('notification.send', 'Enviar notificación', 'NOTIFICATION', 'EXECUTE', 'NOTIFICATION');

INSERT IGNORE INTO ROL_PERMISO (ROL_ID, PERMISO_ID)
SELECT r.ID, p.ID
FROM ROL r
JOIN PERMISO p
WHERE r.CODIGO = 'SWITCH_SERVICE'
  AND p.CODIGO = 'notification.send';

INSERT IGNORE INTO API_CLIENT_SCOPE (API_CLIENT_ID, SCOPE, DESCRIPCION)
SELECT c.ID, 'notification.send', 'Permite al servicio Switch solicitar notificaciones transaccionales'
FROM API_CLIENT c
WHERE c.CLIENT_ID = 'switch-pagos-internos-service';
