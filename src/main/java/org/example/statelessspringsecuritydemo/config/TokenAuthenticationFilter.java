package org.example.statelessspringsecuritydemo.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.statelessspringsecuritydemo.config.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.ServletException;

import java.io.IOException;


public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TokenAuthenticationFilter.class);


    @Autowired
    private JwtTokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        log.info("TokenAuthenticationFilter processing request: {}", request.getRequestURI());

        // Löschen des bestehenden Security-Kontexts, um sicherzustellen, dass wir wirklich stateless arbeiten
        SecurityContextHolder.clearContext();

        try {
            String token = getTokenFromCookie(request);
            log.info("Access token from cookie: {}", token != null ?
                    "present (length: " + token.length() + ")" : "null");

            if (StringUtils.hasText(token) && tokenProvider.validateToken(token)) {
                Authentication auth = tokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(auth);
                log.info("Valid token found, authentication set for user: {}", auth.getName());
            } else {
                log.info("No valid token found in cookie");

                // Wichtig: Authorization-Header prüfen (als Fallback)
                String authHeader = request.getHeader("Authorization");
                if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
                    token = authHeader.substring(7);
                    log.info("Token from Authorization header: {}",
                            token != null ? "present (length: " + token.length() + ")" : "null");

                    if (tokenProvider.validateToken(token)) {
                        Authentication auth = tokenProvider.getAuthentication(token);
                        SecurityContextHolder.getContext().setAuthentication(auth);
                        log.info("Valid token found in header, authentication set for user: {}", auth.getName());
                    }
                }
            }
        } catch (Exception ex) {
            log.error("Could not set user authentication", ex);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private String getTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            log.info("Found {} cookies in request", cookies.length);
            for (Cookie cookie : cookies) {
                log.info("Cookie: {} = {}", cookie.getName(),
                        cookie.getValue() != null ? (cookie.getValue().length() > 5 ?
                                cookie.getValue().substring(0, 5) + "..." : cookie.getValue()) : "null");
                if ("access_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        } else {
            log.info("No cookies in request");
        }
        return null;
    }
}