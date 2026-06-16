# identity-access-service

Banco BanQuito V2 - microservicio transversal de identidad, autenticación, autorización, RBAC, JWT, API clients, scopes, sesiones y auditoría de seguridad.

## Responsabilidad

Este servicio pertenece a la plataforma compartida `com.banquito.platform.identity`. No es exclusivo del Core ni del Switch. Emite tokens y administra seguridad para el ecosistema BanQuito.

Cubre:

- Login de usuarios humanos.
- Refresh token.
- Logout y revocación de sesión.
- Introspección de token.
- Client credentials para clientes técnicos entre sistemas.
- Usuarios, roles, permisos, API clients y scopes.
- Auditoría de seguridad.
- Outbox para eventos futuros de seguridad.

## Rutas principales

```text
POST   /api/v1/auth/login
POST   /api/v1/auth/refresh
POST   /api/v1/auth/logout
POST   /api/v1/auth/introspect
POST   /api/v1/auth/client-token

POST   /api/v1/iam/users
GET    /api/v1/iam/users/{userUuid}
PATCH  /api/v1/iam/users/{userUuid}/status
POST   /api/v1/iam/users/{userUuid}/roles
DELETE /api/v1/iam/users/{userUuid}/roles/{roleCode}

POST   /api/v1/iam/roles
POST   /api/v1/iam/permissions
POST   /api/v1/iam/roles/{roleCode}/permissions
DELETE /api/v1/iam/roles/{roleCode}/permissions/{permissionCode}

POST   /api/v1/iam/api-clients
POST   /api/v1/iam/api-clients/{clientId}/scopes
POST   /api/v1/iam/sessions/{sessionUuid}/revoke
```

## OpenAPI y salud

```text
GET /swagger-ui.html
GET /api-docs
GET /actuator/health
```

## Comunicación

- Hacia usuarios, frontend, backoffice, Core y Switch externo: REST/OpenAPI vía Kong.
- Para validación de JWT en microservicios: los servicios validan localmente con `JWT_SECRET` compartido.
- Contrato gRPC interno preparado en `src/main/proto/identity_service.proto` para introspección/autorización si se requiere integración interna posterior.

## Variables de entorno principales

Ver `.env.example`.

Variables críticas:

```text
SERVER_PORT
IDENTITY_DB_URL
IDENTITY_DB_USER
IDENTITY_DB_PASSWORD
JWT_ISSUER
JWT_SECRET
ACCESS_TOKEN_MINUTES
REFRESH_TOKEN_DAYS
DEMO_DATA_ENABLED
DEMO_PASSWORD
```

## Ejecución local

```powershell
cd C:\banquito-core\identity-access-service
mvn clean package
mvn spring-boot:run
```

## Ejecución Docker

```powershell
docker build -t banquito/identity-access-service:local .
docker run --rm -p 8081:8081 --env-file .env.example banquito/identity-access-service:local
```

Para Docker Compose/cloud se recomienda usar `SPRING_PROFILES_ACTIVE=docker` y `IDENTITY_DB_URL` apuntando al nombre interno del contenedor MySQL, por ejemplo:

```text
jdbc:mysql://mysql-identity:3306/banquito_identity_access_db?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=America/Guayaquil
```

## Estándares aplicados

- Java 21.
- Spring Boot 4.0.6.
- Maven.
- Jakarta Persistence.
- Lombok controlado: `@Getter`, `@Setter`; no `@Data` en entidades.
- Enums con `@Enumerated(EnumType.STRING)`.
- `@Column` explícito.
- `@Version` en entidades mutables.
- `BusinessException`.
- `@RestControllerAdvice`.
- `AuthenticationEntryPoint` y `AccessDeniedHandler` para 401/403 estructurados.
- Variables de entorno para local/cloud.
- Dockerfile listo para nube.

## Seguridad y autorización agregada

El JWT de usuarios humanos ahora incluye contexto de propiedad cuando la identidad está enlazada a un recurso externo:

```json
{
  "referenceUuid": "...",
  "referenceType": "CUSTOMER",
  "customerUuid": "..."
}
```

Esto permite que los microservicios de Core validen autorización horizontal: un cliente solo puede operar recursos asociados a su propio `customerUuid`. También se expone `GET /api/v1/auth/me` para que el frontend pueda identificar rol, scopes y `customerUuid` sin decodificar manualmente el token.

