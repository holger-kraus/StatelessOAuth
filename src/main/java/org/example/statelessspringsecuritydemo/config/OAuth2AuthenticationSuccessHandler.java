package org.example.statelessspringsecuritydemo.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import jakarta.servlet.http.Cookie;

import java.io.IOException;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    private final OAuth2AuthorizedClientService clientService;

    // Konstruktor-Injektion für den Service
    @Autowired
    public OAuth2AuthenticationSuccessHandler(OAuth2AuthorizedClientService clientService) {
        this.clientService = clientService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        logger.debug("OAuth2AuthenticationSuccessHandler invoked");

        try {
            if (!(authentication instanceof OAuth2AuthenticationToken)) {
                logger.error("Authentication is not an OAuth2AuthenticationToken: {}", authentication.getClass().getName());
                super.onAuthenticationSuccess(request, response, authentication);
                return;
            }

            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            logger.debug("OAuth2 authentication successful for user: {}", oauthToken.getName());

            OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(
                    oauthToken.getAuthorizedClientRegistrationId(),
                    oauthToken.getName());

            if (client == null) {
                logger.error("No OAuth2AuthorizedClient found for registration ID: {}",
                        oauthToken.getAuthorizedClientRegistrationId());
                super.onAuthenticationSuccess(request, response, authentication);
                return;
            }

            String accessToken = client.getAccessToken().getTokenValue();
            logger.debug("Access token successfully retrieved, setting cookie");

            // Access-Token in Cookie speichern
            Cookie cookie = new Cookie("access_token", accessToken);
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            // Berechne die Gültigkeitsdauer des Cookies in Sekunden
            long expirySeconds = client.getAccessToken().getExpiresAt()
                    .minusSeconds(Instant.now().getEpochSecond()).getEpochSecond();

            // Setze einen Standardwert, falls die Berechnung fehlschlägt oder negativ ist
            if (expirySeconds <= 0) {
                expirySeconds = 3600; // 1 Stunde Standardwert
                logger.warn("Token expiry calculation resulted in non-positive value, using default: 3600 seconds");
            }

            cookie.setMaxAge((int) expirySeconds);
            // Im Produktiveinsatz solltest du Secure auf true setzen
            // cookie.setSecure(true);

            logger.debug("Setting access_token cookie with expiry in {} seconds", expirySeconds);
            response.addCookie(cookie);

            // Refresh-Token in Cookie speichern
            if (client.getRefreshToken() != null) {
                Cookie refreshCookie = new Cookie("refresh_token", client.getRefreshToken().getTokenValue());
                refreshCookie.setPath("/");
                refreshCookie.setHttpOnly(true);
                refreshCookie.setMaxAge(30 * 24 * 60 * 60); // 30 Tage (Keycloak-Standard)
                // Im Produktiveinsatz: refreshCookie.setSecure(true);
                response.addCookie(refreshCookie);
                logger.debug("refresh_token Cookie gesetzt");
            } else {
                logger.warn("Kein Refresh-Token vom OAuth2-Provider erhalten");
            }
        } catch (Exception e) {
            logger.error("Error in OAuth2AuthenticationSuccessHandler", e);
        }

        // Wichtig: Immer die Super-Methode aufrufen, auch im Fehlerfall
        super.onAuthenticationSuccess(request, response, authentication);
    }
}

