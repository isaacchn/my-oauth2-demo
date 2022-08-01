package me.isaac.oidc_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.JwtClientAssertionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.PublicClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.authorization.web.authentication.*;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;
import java.util.UUID;

@EnableWebSecurity(debug = true)
public class AuthorizationServerConfigV2 {
    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> configurer = new OAuth2AuthorizationServerConfigurer<>();

        configurer
                .registeredClientRepository(this.registeredClientRepository())//1 管理新增和存量的客户端
                .authorizationService(this.authorizationService())//2 管理新增和存量的认证
                .authorizationConsentService(this.authorizationConsentService())//3 管理新增和存量的认证许可
                .providerSettings(this.providerSettings())//4 OAuth2认证服务器设置
                .tokenGenerator(this.tokenGenerator())//5 OAuth2 Token生成器
                .clientAuthentication(//6 OAuth2客户端认证配置
                        oAuth2ClientAuthenticationConfigurer -> oAuth2ClientAuthenticationConfigurer
                                .authenticationConverter(new DelegatingAuthenticationConverter(
                                                Arrays.asList(new JwtClientAssertionAuthenticationConverter(),
                                                        new ClientSecretBasicAuthenticationConverter(),
                                                        new ClientSecretPostAuthenticationConverter(),
                                                        new PublicClientAuthenticationConverter())
                                        )
                                )//The AuthenticationConverter (pre-processor) used when attempting to extract client credentials from HttpServletRequest to an instance of OAuth2ClientAuthenticationToken.
                                .authenticationProvider(new JwtClientAssertionAuthenticationProvider(this.registeredClientRepository(), this.authorizationService()))
                                .authenticationProvider(new ClientSecretAuthenticationProvider(this.registeredClientRepository(), this.authorizationService()))
                                .authenticationProvider(new PublicClientAuthenticationProvider(this.registeredClientRepository(), this.authorizationService()))//The AuthenticationProvider (main processor) used for authenticating the OAuth2ClientAuthenticationToken. (One or more may be added to replace the defaults.)
                                .authenticationSuccessHandler(null)//todo The AuthenticationSuccessHandler (post-processor) used for handling a successful client authentication and associating the OAuth2ClientAuthenticationToken to the SecurityContext.
                                .errorResponseHandler(null))//The AuthenticationFailureHandler (post-processor) used for handling a failed client authentication and returning the OAuth2Error response.
                .authorizationEndpoint(oAuth2AuthorizationEndpointConfigurer -> {
                })//7 OAuth2认证端点配置
                .tokenEndpoint(oAuth2TokenEndpointConfigurer -> {
                })//8 OAuth2 Token端点配置
                .tokenIntrospectionEndpoint(oAuth2TokenIntrospectionEndpointConfigurer -> {
                })//9 OAuth2 Token自解析端点配置
                .tokenRevocationEndpoint(oAuth2TokenRevocationEndpointConfigurer -> {
                })//10 OAuth2 Token撤回端点配置
                .oidc(oidcConfigurer -> oidcConfigurer
                        .userInfoEndpoint(oidcUserInfoEndpointConfigurer -> {
                        })//11 OIDC userinfo端点配置
                        .clientRegistrationEndpoint(oidcClientRegistrationEndpointConfigurer -> {
                        })//12 OIDC客户端注册端点配置
                );

        http.apply(configurer);
        return http.build();
    }

    private RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("login-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:18070/login/oauth2/code/login-client")
                .redirectUri("http://127.0.0.1:18070/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    private OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    private OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    private ProviderSettings providerSettings() {
        return ProviderSettings
                .builder()//默认配置的builder
                .build();
    }

    private OAuth2TokenGenerator<?> tokenGenerator() {
        JwtEncoder jwtEncoder = null;//todo
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }
}
