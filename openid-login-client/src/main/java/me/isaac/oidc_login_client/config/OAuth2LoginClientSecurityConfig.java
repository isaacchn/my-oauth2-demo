package me.isaac.oidc_login_client.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity(debug = true)
@Slf4j
public class OAuth2LoginClientSecurityConfig{
    //覆盖SpringBoot Auto-configuration
    //OAuth2ClientAutoConfiguration
    //注册ClientRegistrationRepository @Bean composed of ClientRegistration(s) from the configured OAuth Client properties
    //注册SecurityFilterChain @Bean and enables OAuth 2.0 Login through httpSecurity.oauth2Login()

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2.authorizationEndpoint(authorizationEndpointConfig -> authorizationEndpointConfig

                                //.authorizationRequestResolver(authorizationRequestResolver(clientRegistrationRepository()))
                                .authorizationRequestRepository(authorizationRequestRepository())
                        )
                )

                .oauth2Client(oauth2 -> oauth2
                                .clientRegistrationRepository(this.clientRegistrationRepository())
                                .authorizationCodeGrant(codeGrant -> codeGrant
                                        .accessTokenResponseClient(this.accessTokenResponseClient())
                                )

//                        .authorizedClientRepository(this.authorizedClientRepository())
//                        .authorizedClientService(this.authorizedClientService())
//                        .authorizationCodeGrant(codeGrant -> codeGrant
//                                .authorizationRequestRepository(this.authorizationRequestRepository())
//                                .authorizationRequestResolver(this.authorizationRequestResolver())
//                                .accessTokenResponseClient(this.accessTokenResponseClient())
//                        )
                );
        return http.build();
    }

//    @Bean
//    public OAuth2AuthorizedClientManager authorizedClientManager(
//            ClientRegistrationRepository clientRegistrationRepository,
//            OAuth2AuthorizedClientRepository authorizedClientRepository) {
//
//        OAuth2AuthorizedClientProvider authorizedClientProvider =
//                OAuth2AuthorizedClientProviderBuilder.builder()
//                        .clientCredentials()
//                        .build();
//
//        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
//                new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
//        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
//
//        return authorizedClientManager;
//    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.myClientRegistration());
    }

    private ClientRegistration myClientRegistration() {
        return ClientRegistrations.fromIssuerLocation("http://localhost:19000")
                .registrationId("my-spring-authorization-server")
                .clientId("login-client")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:18070/login/oauth2/code/login-client")
                .scope("openid", "profile")
                .clientName("New-My-Client-Name")
                .build();
    }

    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        return new OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>() {
            private final DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();

            @Override
            public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
                return client.getTokenResponse(authorizationGrantRequest);
            }
        };
    }

//    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
//        InvocationHandler handler = new InvocationHandler() {
//            final DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
//
//            @Override
//            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
//
//                if (method.getName().equals("getTokenResponse")) {
//                    OAuth2AccessTokenResponse result = client.getTokenResponse((OAuth2AuthorizationCodeGrantRequest) args[0]);
//                    return result;
//                } else {
//                    Class<?>[] parameterTypes = new Class<?>[args.length];
//                    for (int i = 0; i < args.length; i++) {
//                        parameterTypes[i] = args[i].getClass();
//                    }
//                    Method invokeMethod = client.getClass().getMethod(method.getName(), parameterTypes);
//                    return invokeMethod.invoke(proxy, args);
//                }
//            }
//        };
//        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> obj
//                = (OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>) Proxy.newProxyInstance(
//                OAuth2AccessTokenResponseClient.class.getClassLoader(),
//                new Class[]{OAuth2AccessTokenResponseClient.class},
//                handler
//        );
//        return obj;
//    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, "/oauth2/authorization");
        authorizationRequestResolver.setAuthorizationRequestCustomizer(
                authorizationRequestCustomizer());

        return authorizationRequestResolver;
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
        return new Consumer<OAuth2AuthorizationRequest.Builder>() {
            @Override
            public void accept(OAuth2AuthorizationRequest.Builder builder) {
                //do nothing
            }
        };
    }

    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        HttpSessionOAuth2AuthorizationRequestRepository repository = new HttpSessionOAuth2AuthorizationRequestRepository();
        return new AuthorizationRequestRepository<OAuth2AuthorizationRequest>() {
            @Override
            public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
                return repository.loadAuthorizationRequest(request);
            }

            @Override
            public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
                repository.saveAuthorizationRequest(authorizationRequest, request, response);
            }

            @Override
            public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
                log.info(">>> 接收到OIDC Provider的回调请求");
                Map<String, String[]> map = request.getParameterMap();
                for (String key : map.keySet()) {
                    log.info("请求参数： {} = {}", key, String.join(",", Arrays.asList(map.get(key))));
                }
                log.info("<<< 结束");
                return repository.removeAuthorizationRequest(request);
            }
        };
    }
}
