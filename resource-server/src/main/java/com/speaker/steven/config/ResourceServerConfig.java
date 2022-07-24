package com.speaker.steven.config;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Steven
 */
@EnableWebSecurity(debug = true)
public class ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authorize -> {
                    try {
                        authorize
                                .mvcMatchers("/accounts/**").hasAuthority("SCOPE_accounts.read")
                                .antMatchers(HttpMethod.POST, "/accounts/*").hasAuthority("SCOPE_accounts.write")
                                .anyRequest().authenticated()
                                .and().csrf().disable();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .oauth2ResourceServer(
                        OAuth2ResourceServerConfigurer::jwt
                );
        return http.build();
    }

}