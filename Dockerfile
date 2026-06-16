FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:21-jre
LABEL org.opencontainers.image.title="identity-access-service" \
      org.opencontainers.image.description="Banco BanQuito V2 - Identity, JWT, RBAC and API clients" \
      org.opencontainers.image.vendor="Banco BanQuito"

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system banquito \
    && adduser --system --ingroup banquito banquito
COPY --from=build /workspace/target/*.jar app.jar
RUN chown -R banquito:banquito /app
USER banquito

ENV SERVER_PORT=8081 \
    SPRING_PROFILES_ACTIVE=docker \
    JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseContainerSupport"

EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=5 \
  CMD curl -fsS http://127.0.0.1:${SERVER_PORT}/actuator/health || exit 1

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]
