package com.speaker.steven.config;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.security.KeyStore;
import java.util.function.Function;

/**
 * @author Steven
 */
@Configuration
public class OAuth2ClientConfig {

	@Bean
	@SneakyThrows
	public JWKSource<SecurityContext> jwkSource() {
		String keyStorePath = "coscup.jks";
		String alias = "coscup";
		String storePass = "666666";

		ClassPathResource resource = new ClassPathResource(keyStorePath);
		KeyStore jks = KeyStore.getInstance("jks");
		char[] pin = storePass.toCharArray();
		jks.load(resource.getInputStream(), pin);
		RSAKey rsaKey = RSAKey.load(jks, alias, pin);

		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	Function<ClientRegistration, JWK> jwkResolver(JWKSource<SecurityContext> jwkSource) {
		JWKSelector jwkSelector = new JWKSelector(new JWKMatcher.Builder().privateOnly(true).build());
		return (registration) -> {
			JWKSet jwkSet = null;
			try {
				jwkSet = new JWKSet(jwkSource.get(jwkSelector, null));
			} catch (Exception ex) { }
			return jwkSet != null ? jwkSet.getKeys().iterator().next() : null;
		};
	}

	@Bean
	OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeTokenResponseClient(
			Function<ClientRegistration, JWK> jwkResolver) {

		OAuth2AuthorizationCodeGrantRequestEntityConverter authorizationCodeGrantRequestEntityConverter =
				new OAuth2AuthorizationCodeGrantRequestEntityConverter();
		authorizationCodeGrantRequestEntityConverter.addParametersConverter(
				new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver));

		DefaultAuthorizationCodeTokenResponseClient authorizationCodeTokenResponseClient =
				new DefaultAuthorizationCodeTokenResponseClient();
		authorizationCodeTokenResponseClient.setRequestEntityConverter(authorizationCodeGrantRequestEntityConverter);

		return authorizationCodeTokenResponseClient;
	}

	@Bean
	OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenTokenResponseClient(
			Function<ClientRegistration, JWK> jwkResolver) {

		OAuth2RefreshTokenGrantRequestEntityConverter refreshTokenGrantRequestEntityConverter =
				new OAuth2RefreshTokenGrantRequestEntityConverter();
		refreshTokenGrantRequestEntityConverter.addParametersConverter(
				new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver));
		refreshTokenGrantRequestEntityConverter.addParametersConverter(authorizationGrantRequest -> {
			MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
			parameters.add(OAuth2ParameterNames.CLIENT_ID, authorizationGrantRequest.getClientRegistration().getClientId());
			return parameters;
		});

		DefaultRefreshTokenTokenResponseClient refreshTokenTokenResponseClient =
				new DefaultRefreshTokenTokenResponseClient();
		refreshTokenTokenResponseClient.setRequestEntityConverter(refreshTokenGrantRequestEntityConverter);

		return refreshTokenTokenResponseClient;
	}

	@Bean
	OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient(
			Function<ClientRegistration, JWK> jwkResolver) {

		OAuth2ClientCredentialsGrantRequestEntityConverter clientCredentialsGrantRequestEntityConverter =
				new OAuth2ClientCredentialsGrantRequestEntityConverter();
		clientCredentialsGrantRequestEntityConverter.addParametersConverter(
				new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver));
		clientCredentialsGrantRequestEntityConverter.addParametersConverter(authorizationGrantRequest -> {
			MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
			parameters.add(OAuth2ParameterNames.CLIENT_ID, authorizationGrantRequest.getClientRegistration().getClientId());
			return parameters;
		});

		DefaultClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient =
				new DefaultClientCredentialsTokenResponseClient();
		clientCredentialsTokenResponseClient.setRequestEntityConverter(clientCredentialsGrantRequestEntityConverter);

		return clientCredentialsTokenResponseClient;
	}

}
