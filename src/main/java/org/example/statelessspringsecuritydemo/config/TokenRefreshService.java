package org.example.statelessspringsecuritydemo.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Component
public class TokenRefreshService {

    private static final Logger log = LoggerFactory.getLogger(TokenRefreshService.class);

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final RestTemplate restTemplate;

    public TokenRefreshService(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.restTemplate = new RestTemplate();
    }

    /**
     * Tauscht ein Refresh-Token gegen neue Tokens ein.
     *
     * @param refreshToken das aktuelle Refresh-Token
     * @return TokenRefreshResult mit neuen Tokens, oder null bei Fehler
     */
    public TokenRefreshResult refreshTokens(String refreshToken) {
        try {
            ClientRegistration registration = clientRegistrationRepository.findByRegistrationId("keycloak");
            String tokenUri = registration.getProviderDetails().getTokenUri();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "refresh_token");
            params.add("refresh_token", refreshToken);
            params.add("client_id", registration.getClientId());
            params.add("client_secret", registration.getClientSecret());

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);

            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> response =
                    (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>) restTemplate.postForEntity(tokenUri, entity, Map.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Map<String, Object> body = response.getBody();
                String newAccessToken = (String) body.get("access_token");
                String newRefreshToken = body.containsKey("refresh_token")
                        ? (String) body.get("refresh_token")
                        : refreshToken;

                int expiresIn = 300;
                Object expiresInObj = body.get("expires_in");
                if (expiresInObj instanceof Number) {
                    expiresIn = ((Number) expiresInObj).intValue();
                }

                log.debug("Token-Refresh erfolgreich, neues Access-Token erhalten (läuft in {} Sekunden ab)", expiresIn);
                return new TokenRefreshResult(newAccessToken, newRefreshToken, expiresIn);
            }

            log.warn("Token-Refresh fehlgeschlagen: HTTP {}", response.getStatusCode());
        } catch (Exception e) {
            log.warn("Token-Refresh fehlgeschlagen: {}", e.getMessage());
        }
        return null;
    }

    public record TokenRefreshResult(String accessToken, String refreshToken, int expiresIn) {}
}
