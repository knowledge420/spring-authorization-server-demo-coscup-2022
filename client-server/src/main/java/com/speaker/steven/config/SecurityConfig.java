package com.speaker.steven.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Steven
 */
@EnableWebSecurity(debug = true)
public class SecurityConfig {

    @Autowired
    OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeTokenResponseClient;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .authorizationEndpoint()
                        .and()
                        .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                .accessTokenResponseClient(this.authorizationCodeTokenResponseClient))
                        .defaultSuccessUrl("/loginSuccess")
                        .failureUrl("/loginFailure")
                )
                .oauth2Client(oauth2Client -> oauth2Client
                        .authorizationCodeGrant(authorizationCodeGrant -> authorizationCodeGrant
                                .accessTokenResponseClient(this.authorizationCodeTokenResponseClient))
        );
        return http.build();
    }
}