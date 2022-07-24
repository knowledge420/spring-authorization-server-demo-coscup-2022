package com.speaker.steven.events;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.stereotype.Component;

/**
 * @author Steven
 */
@Component
@Slf4j
public class AuthEvents {

	@Async
	@EventListener
	public void onSuccess(AuthenticationSuccessEvent success) {
		log.info("AuthenticationSuccessEvent: 發送登入成功信");
	}

	@Async
	@EventListener
	public void onFailure(AbstractAuthenticationFailureEvent failure) {
		log.info("AbstractAuthenticationFailureEvent: 發送登入失敗信");
	}

	@Async
	@EventListener
	public void onSuccess(AuthorizationGrantedEvent success) {
		log.info("AuthorizationGrantedEvent: 發送授權成功信");
	}

	@Async
	@EventListener
	public void onFailure(AuthorizationDeniedEvent failure) {
		log.info("AuthorizationDeniedEvent: 發送授權失敗信");
	}

}