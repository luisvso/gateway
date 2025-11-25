package br.ucsal.gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import javax.crypto.spec.SecretKeySpec;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${api.security.token.secret}")
    private String secretKey;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/auth/login").permitAll()
                        .pathMatchers(HttpMethod.POST, "/auth/register").hasRole("ADMIN")

                        .pathMatchers("/api/espacos/**").hasRole("ADMIN")

                        .pathMatchers(HttpMethod.POST, "/reservas").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.PUT, "/reservas/{id}").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.DELETE, "/reservas/{id}").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/reservas/{id}").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/reservas").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/reservas/espaco/{espacoId}").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/reservas/alocadas").hasRole("PROFESSOR")

                        .pathMatchers("/professor/**").hasRole("ADMIN")

                        .pathMatchers(HttpMethod.POST, "/software").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/software/findAll").hasRole("PROFESSOR")
                        .pathMatchers(HttpMethod.PUT, "/software/{id}").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/software/{id}").hasRole("PROFESSOR")
                        .pathMatchers(HttpMethod.DELETE, "/software/{id}").hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/software/exists/{id}").hasRole("PROFESSOR")

                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtDecoder(jwtDecoder())
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())))
                .build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        var secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
        return NimbusReactiveJwtDecoder.withSecretKey(secretKeySpec)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }

    @Bean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        grantedAuthoritiesConverter.setAuthoritiesClaimName("role");

        ReactiveJwtAuthenticationConverter jwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
                new ReactiveJwtGrantedAuthoritiesConverterAdapter(grantedAuthoritiesConverter));

        return jwtAuthenticationConverter;
    }
}
