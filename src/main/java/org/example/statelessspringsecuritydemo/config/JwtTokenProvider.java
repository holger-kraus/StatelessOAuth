package org.example.statelessspringsecuritydemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    @Autowired
    private ReactiveJwtDecoder jwtDecoder;

    public boolean validateToken(String token) {
        try {
            jwtDecoder.decode(token).block();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Authentication getAuthentication(String token) {
        Jwt jwt = jwtDecoder.decode(token).block();

        Collection<? extends GrantedAuthority> authorities = extractAuthorities(jwt);

        String username = jwt.getClaimAsString("preferred_username");
        User principal = new User(username, "", authorities);

        return new JwtAuthenticationToken(jwt, authorities, username);
    }

    private Collection<? extends GrantedAuthority> extractAuthorities(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        List<String> roles = new ArrayList<>();

        if (realmAccess != null && realmAccess.containsKey("roles")) {
            roles = (List<String>) realmAccess.get("roles");
        }

        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }
}
