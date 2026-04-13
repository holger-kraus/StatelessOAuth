package org.example.statelessspringsecuritydemo.config;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;


    private CookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository;

    @Autowired
    public SecurityConfig(OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                          CookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository) {
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
        this.cookieAuthorizationRequestRepository = cookieAuthorizationRequestRepository;
    }

    @Bean
    public RequestCache requestCache() {
        return new NullRequestCache();
    }

    @Bean
    public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
        return new StatelessWebAuthenticationDetailsSource();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // .csrf().disable() veraltet; verwende stattdessen:
                .csrf(AbstractHttpConfigurer::disable)

                // .authorizeRequests() veraltet; verwende stattdessen:
                .authorizeHttpRequests(authorize -> authorize
                        // .antMatchers() veraltet; verwende stattdessen:
                        .requestMatchers("/", "/public/**").permitAll()
                        .anyRequest().authenticated()
                ).requestCache(cache -> cache
                        .requestCache(requestCache())
                )

                // OAuth2 Login Konfguration
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(endpoint -> endpoint
                                .baseUri("/oauth2/authorization")
                                .authorizationRequestRepository(cookieAuthorizationRequestRepository)
                        )
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureUrl("/login?error=true")
                        .authenticationDetailsSource(authenticationDetailsSource())
                )

                // Session-Management
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
                )

                // Filter hinzufügen
                .addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                // Logout-Konfiguration
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                        .deleteCookies("access_token", "refresh_token")
                );

        return http.build();
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }
    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        // Verwende eine Strategy, die keine Sessions erstellt
        return new NullAuthenticatedSessionStrategy();
    }
}