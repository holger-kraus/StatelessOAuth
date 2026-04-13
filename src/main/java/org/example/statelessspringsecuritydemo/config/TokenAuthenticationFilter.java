package org.example.statelessspringsecuritydemo.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    @Autowired
    private TokenRefreshService tokenRefreshService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        log.info("TokenAuthenticationFilter processing request: {}", request.getRequestURI());

        // Löschen des bestehenden Security-Kontexts – echtes stateless Verhalten
        SecurityContextHolder.clearContext();

        try {
            String token = getCookieValue(request, "access_token");
            log.info("Access token from cookie: {}", token != null ?
                    "vorhanden (Länge: " + token.length() + ")" : "null");

            if (StringUtils.hasText(token) && tokenProvider.validateToken(token)) {
                // Token gültig → direkt authentifizieren
                setAuthentication(token);
                log.info("Gültiges Token gefunden, Authentifizierung gesetzt");

            } else if (StringUtils.hasText(token) && tokenProvider.isTokenExpired(token)) {
                // Token abgelaufen → Refresh versuchen
                log.info("Access-Token abgelaufen, versuche Token-Refresh");
                boolean refreshed = tryRefreshToken(request, response);
                if (!refreshed) {
                    log.info("Token-Refresh fehlgeschlagen, Cookies werden gelöscht");
                    clearTokenCookies(response);
                }

            } else {
                // Kein Cookie-Token → Authorization-Header prüfen (Fallback für API-Clients)
                log.info("Kein gültiges Token im Cookie, prüfe Authorization-Header");
                String authHeader = request.getHeader("Authorization");
                if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
                    String headerToken = authHeader.substring(7);
                    log.info("Token aus Authorization-Header: {}",
                            headerToken.length() > 5 ? headerToken.substring(0, 5) + "..." : "kurz");
                    if (tokenProvider.validateToken(headerToken)) {
                        setAuthentication(headerToken);
                        log.info("Gültiges Token im Header, Authentifizierung gesetzt");
                    }
                }
            }
        } catch (Exception ex) {
            log.error("Fehler beim Setzen der Authentifizierung", ex);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private void setAuthentication(String token) {
        Authentication auth = tokenProvider.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(auth);
        log.info("Authentifizierung gesetzt für Benutzer: {}", auth.getName());
    }

    private boolean tryRefreshToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = getCookieValue(request, "refresh_token");
        if (!StringUtils.hasText(refreshToken)) {
            log.info("Kein refresh_token Cookie vorhanden");
            return false;
        }

        TokenRefreshService.TokenRefreshResult result = tokenRefreshService.refreshTokens(refreshToken);
        if (result == null) {
            log.warn("Token-Refresh lieferte kein Ergebnis");
            return false;
        }

        // Neues Access-Token Cookie setzen
        Cookie accessCookie = new Cookie("access_token", result.accessToken());
        accessCookie.setPath("/");
        accessCookie.setHttpOnly(true);
        accessCookie.setMaxAge(result.expiresIn());
        // accessCookie.setSecure(true);
        response.addCookie(accessCookie);

        // Rotiertes Refresh-Token Cookie setzen
        Cookie refreshCookie = new Cookie("refresh_token", result.refreshToken());
        refreshCookie.setPath("/");
        refreshCookie.setHttpOnly(true);
        refreshCookie.setMaxAge(30 * 24 * 60 * 60); // 30 Tage
        // refreshCookie.setSecure(true);
        response.addCookie(refreshCookie);

        // Mit neuem Token authentifizieren
        if (tokenProvider.validateToken(result.accessToken())) {
            setAuthentication(result.accessToken());
            log.info("Token erfolgreich aktualisiert, Authentifizierung gesetzt");
            return true;
        }

        log.warn("Neues Access-Token nach Refresh ungültig");
        return false;
    }

    private void clearTokenCookies(HttpServletResponse response) {
        Cookie accessCookie = new Cookie("access_token", "");
        accessCookie.setPath("/");
        accessCookie.setHttpOnly(true);
        accessCookie.setMaxAge(0);
        response.addCookie(accessCookie);

        Cookie refreshCookie = new Cookie("refresh_token", "");
        refreshCookie.setPath("/");
        refreshCookie.setHttpOnly(true);
        refreshCookie.setMaxAge(0);
        response.addCookie(refreshCookie);
    }

    private String getCookieValue(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
