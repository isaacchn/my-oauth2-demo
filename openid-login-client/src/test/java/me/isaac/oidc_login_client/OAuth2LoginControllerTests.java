package me.isaac.oidc_login_client;

import java.util.Collections;

import me.isaac.oidc_login_client.controller.OAuth2LoginController;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;

/**
 * Tests for {@link OAuth2LoginController}
 *
 * @author Josh Cummings
 */
@WebMvcTest(OAuth2LoginController.class)
public class OAuth2LoginControllerTests {

    @Autowired
    MockMvc mvc;

    @MockBean
    ClientRegistrationRepository clientRegistrationRepository;

    @Test
    void rootWhenAuthenticatedReturnsUserAndClient() throws Exception {
        // @formatter:off
        this.mvc.perform(get("/").with(oauth2Login()))
                .andExpect(model().attribute("userName", "user"))
                .andExpect(model().attribute("clientName", "test"))
                .andExpect(model().attribute("userAttributes", Collections.singletonMap("sub", "user")));
        // @formatter:on
    }

    @Test
    void rootWhenOverridingClientRegistrationReturnsAccordingly() throws Exception {
        // @formatter:off
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("test")
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .clientId("my-client-id")
                .clientName("my-client-name")
                .tokenUri("https://token-uri.example.org")
                .build();

        this.mvc.perform(get("/").with(oauth2Login()
                .clientRegistration(clientRegistration)
                .attributes((a) -> a.put("sub", "spring-security"))))
                .andExpect(model().attribute("userName", "spring-security"))
                .andExpect(model().attribute("clientName", "my-client-name"))
                .andExpect(model().attribute("userAttributes", Collections.singletonMap("sub", "spring-security")));
        // @formatter:on
    }

    @TestConfiguration
    static class AuthorizedClient {

        @Bean
        OAuth2AuthorizedClientRepository authorizedClientRepository() {
            return new HttpSessionOAuth2AuthorizedClientRepository();
        }

    }

}