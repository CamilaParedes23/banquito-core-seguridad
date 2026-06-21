-- R9-G: onboarding digital de clientes naturales/jurídicos y rol empresarial para Switch.
INSERT IGNORE INTO PARAMETRO_SEGURIDAD (CODIGO,NOMBRE,VALOR_TEXTO,TIPO_DATO,DESCRIPCION) VALUES
('CUSTOMER_ACTIVATION_TOKEN_MINUTES','Vigencia activación cliente','1440','INTEGER','Minutos de validez del token de activación digital para clientes');

INSERT IGNORE INTO ROL (CODIGO,NOMBRE,TIPO_ROL,DESCRIPCION) VALUES
('CLIENTE_EMPRESA_PAGOS_MASIVOS','Cliente empresa pagos masivos','CLIENTE','Acceso empresarial al portal de pagos masivos del Switch');

INSERT IGNORE INTO PERMISO (CODIGO,NOMBRE,MODULO,ACCION,RECURSO) VALUES
('switch.batch.read','Consultar lotes de pagos masivos','SWITCH','READ','BATCH'),
('switch.batch.upload','Cargar lotes de pagos masivos','SWITCH','CREATE','BATCH'),
('switch.batch.confirm','Confirmar lotes de pagos masivos','SWITCH','APPROVE','BATCH'),
('switch.batch.cancel','Cancelar lotes de pagos masivos','SWITCH','CANCEL','BATCH'),
('switch.report.read','Consultar reportes de pagos masivos','SWITCH','READ','REPORT'),
('switch.report.download','Descargar reportes de pagos masivos','SWITCH','DOWNLOAD','REPORT'),
('switch.tariff.read','Consultar tarifas de pagos masivos','SWITCH','READ','TARIFF'),
('switch.company.profile.read','Consultar perfil empresarial del Switch','SWITCH','READ','COMPANY_PROFILE');

INSERT IGNORE INTO ROL_PERMISO (ROL_ID, PERMISO_ID)
SELECT r.ID, p.ID
FROM ROL r
JOIN PERMISO p
WHERE r.CODIGO = 'CLIENTE_EMPRESA_PAGOS_MASIVOS'
  AND p.CODIGO IN (
    'switch.batch.read',
    'switch.batch.upload',
    'switch.batch.confirm',
    'switch.batch.cancel',
    'switch.report.read',
    'switch.report.download',
    'switch.tariff.read',
    'switch.company.profile.read'
  );
