package com.yntec.apigateway.security;

import io.jsonwebtoken.Claims;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter extends AbstractGatewayFilterFactory<JwtAuthFilter.Config> {

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            // Allow CORS preflight requests to pass through without JWT validation
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequest().getMethod().toString())) {
                return chain.filter(exchange);
            }

            String path = exchange.getRequest().getURI().getPath();
            if (path.contains("/mfa/add-mfa-and-challenge") || path.contains("/login-user")
                    || path.contains("/login-with-mfa")) {
                return chain.filter(exchange);
            }
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return unauthorized(exchange);
            }

            String token = authHeader.substring(7);

            try {
                Claims claims = jwtUtil.validate(token);

                // Extract first organization and branch from arrays

                // Forward JWT-derived headers to downstream services
                var mutatedRequest = exchange.getRequest().mutate()
                        .header("X-USER-Id", claims.getSubject())
                        .header("X-ORG-Id", claims.get("organizationId", String.class))
                        .header("X-BRANCH-Id", claims.get("branchId", String.class))
                        .build();

                var mutatedExchange = exchange.mutate()
                        .request(mutatedRequest)
                        .build();

                return chain.filter(mutatedExchange);

            } catch (Exception e) {
                return unauthorized(exchange);
            }
        };
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    public static class Config {
        // empty for now
    }
}