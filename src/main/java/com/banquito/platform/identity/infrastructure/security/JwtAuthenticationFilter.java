package com.banquito.platform.identity.infrastructure.security;

import com.banquito.platform.identity.api.dto.internal.AuthenticatedActor;
import com.banquito.platform.identity.domain.enums.EstadoSesionEnum;
import com.banquito.platform.identity.domain.repository.SesionUsuarioRepository;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final String SERVICE_ACTOR_TYPE = "SERVICIO";

    private final JwtService jwtService;
    private final SesionUsuarioRepository sesionRepository;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   SesionUsuarioRepository sesionRepository) {
        this.jwtService = jwtService;
        this.sesionRepository = sesionRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String token = authorization.substring(7);
            try {
                Claims claims = jwtService.parseClaims(token);
                String actorType = (String) claims.get("actorType");

                if (!SERVICE_ACTOR_TYPE.equalsIgnoreCase(actorType) && !hasActiveHumanSession(claims)) {
                    SecurityContextHolder.clearContext();
                    filterChain.doFilter(request, response);
                    return;
                }

                Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                List<?> scopes = claims.get("scopes", List.class);
                if (scopes != null) {
                    scopes.forEach(scope -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope)));
                }
                List<?> roles = claims.get("roles", List.class);
                if (roles != null) {
                    roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
                }
                AuthenticatedActor actor = new AuthenticatedActor(
                        claims.getSubject(),
                        (String) claims.get("username"),
                        actorType,
                        (String) claims.get("clientId"),
                        toStringList(roles),
                        toStringList(scopes),
                        (String) claims.get("referenceUuid"),
                        (String) claims.get("referenceType"),
                        (String) claims.get("customerUuid")
                );
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        actor, null, authorities
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception ignored) {
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request, response);
    }

    private boolean hasActiveHumanSession(Claims claims) {
        String jti = claims.getId();
        String subject = claims.getSubject();

        if (jti == null || jti.isBlank() || subject == null || subject.isBlank()) {
            return false;
        }

        return sesionRepository.existsByAccessTokenJtiAndEstadoAndUsuario_UuidUsuario(
                jti,
                EstadoSesionEnum.ACTIVA,
                subject
        );
    }

    private List<String> toStringList(List<?> values) {
        if (values == null) return List.of();
        return values.stream().map(String::valueOf).toList();
    }
}
