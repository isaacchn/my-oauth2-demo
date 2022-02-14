package me.isaac.oauth_server;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configuration
@EnableAuthorizationServer
public class Oauth2AuthorizationServerConfigurer extends AuthorizationServerConfigurerAdapter {
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("webapp")
                .secret("secret")
                .authorizedGrantTypes("authorization code")
                .scopes("user_info")
                .autoApprove(true)
                .accessTokenValiditySeconds(3600);
    }
}
