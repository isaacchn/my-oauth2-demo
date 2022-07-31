package me.isaac.oidc_login_client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

//@Configuration
public class OAuth2LoginConfig {
    //覆盖SpringBoot Auto-configuration
    //OAuth2ClientAutoConfiguration
    //注册ClientRegistrationRepository @Bean composed of ClientRegistration(s) from the configured OAuth Client properties
    //注册SecurityFilterChain @Bean and enables OAuth 2.0 Login through httpSecurity.oauth2Login()

//    @Bean
//    public ClientRegistrationRepository clientRegistrationRepository() {
//        return new InMemoryClientRegistrationRepository(this.myClientRegistration());
//    }

//    private ClientRegistration myClientRegistration() {
//        return ClientRegistrations.fromIssuerLocation("http://localhost:19000")
//                .registrationId("my-spring-authorization-server")
//                .clientId("login-client")
//                .clientSecret("secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .redirectUri("http://127.0.0.1:18070/login/oauth2/code/login-client")
//                .scope("openid", "profile")
//                .clientName("New-My-Client-Name")
//                .build();
//
////        return ClientRegistration.withRegistrationId("my-spring-authorization-server")
////                .clientId("login-client")
////                .clientSecret("secret")
////                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
////                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
////                .redirectUri("http://127.0.0.1:18070/login/oauth2/code/login-client")
////                .scope("openid", "profile")
////                .issuerUri("http://localhost:19000/")
//////                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
//////                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
//////                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
//////                .userNameAttributeName(IdTokenClaimNames.SUB)
//////                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
////                .clientName("New-My-Client-Name")
////                .build();
//
//
//    }
}
