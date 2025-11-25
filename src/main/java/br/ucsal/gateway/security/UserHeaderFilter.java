package br.ucsal.gateway.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class UserHeaderFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .filter(c -> c.getAuthentication() instanceof JwtAuthenticationToken)
                .flatMap(c -> {
                    JwtAuthenticationToken auth = (JwtAuthenticationToken) c.getAuthentication();

                    Jwt jwt = (Jwt) auth.getPrincipal();

                    String userId = String.valueOf(jwt.getClaims().get("id"));
                    String role = String.valueOf(jwt.getClaims().get("role"));

                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(r -> r.headers(headers -> {
                                headers.add("X-User-Id", userId);
                                headers.add("X-User-Role", role);
                            }))
                            .build();

                    return chain.filter(mutatedExchange);
                })
                .switchIfEmpty(chain.filter(exchange));
    }
}
