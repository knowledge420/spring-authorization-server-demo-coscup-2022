package com.speaker.steven.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Steven
 */
@RestController
public class AccountsController {

    private static String[] accounts = new String[]{"Account 1", "Account 2", "Account 3"};

    @Autowired
    private WebClient webClient;

    @GetMapping("/loginSuccess")
    public String loginSuccess(
            @RegisteredOAuth2AuthorizedClient("open-banking-idp")
            OAuth2AuthorizedClient authorizedClient) {
        return "loginSuccess";
    }

    @GetMapping("/loginFailure")
    public String loginFailure(
            @RegisteredOAuth2AuthorizedClient("open-banking-idp")
            OAuth2AuthorizedClient authorizedClient) {
        return "loginFailure";
    }

    @GetMapping(value = "/accounts")
    public String[] getAccountsFromResourceServer(
      @RegisteredOAuth2AuthorizedClient("open-banking-idp")
      OAuth2AuthorizedClient authorizedClient) {
        return this.webClient
                .get()
                .uri("http://127.0.0.1:8090/accounts")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String[].class)
                .block();
    }

    @GetMapping("/accounts/{accountName}")
    public String[] createAccount(
            @RegisteredOAuth2AuthorizedClient("open-banking-idp")
            OAuth2AuthorizedClient authorizedClient,
            @PathVariable("accountName") String accountName) {
        StringBuilder stringBuilder = new StringBuilder("http://127.0.0.1:8090/accounts/");
        return webClient
                .post()
                .uri(stringBuilder.append(accountName).toString())
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String[].class)
                .block();
    }

    @GetMapping(value = "/client/accounts")
    public String[] getAccountsInClientServer(@RegisteredOAuth2AuthorizedClient("github-idp")
            OAuth2AuthorizedClient authorizedClient) {
        return accounts;
    }

}