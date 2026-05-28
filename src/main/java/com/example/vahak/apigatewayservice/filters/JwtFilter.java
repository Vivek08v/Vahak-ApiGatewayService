package com.example.vahak.apigatewayservice.filters;

import com.example.vahak.apigatewayservice.services.JwtService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtFilter implements WebFilter {

    private final JwtService jwtService;

    public JwtFilter(JwtService jwtService){
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             WebFilterChain chain) {

//        System.out.println("HII1");
        ServerHttpRequest request = exchange.getRequest();

        String authHeader =
                request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // No token present
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(7);

        try {
//            System.out.println("HII2");

            if (!jwtService.validateToken2(token)) {

                exchange.getResponse()
                        .setStatusCode(HttpStatus.UNAUTHORIZED);

                return exchange.getResponse().setComplete();
            }
//            System.out.println("HII3");

            String username = jwtService.extractEmail(token);

            List<GrantedAuthority> authorities =
                    List.of(new SimpleGrantedAuthority("PASSENGER"));

            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            username,
                            null,
                            authorities
                    );

            SecurityContext context = new SecurityContextImpl(authentication);
//            System.out.println("HII4: "+username);
            return chain.filter(exchange)
                    .contextWrite(
                            ReactiveSecurityContextHolder
                                    .withSecurityContext(
                                            Mono.just(context)
                                    )
                    );

        } catch (Exception e) {
            System.out.println("Error in JwtFilter: "+e);
            exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);

            return exchange.getResponse().setComplete();
        }
    }
}
