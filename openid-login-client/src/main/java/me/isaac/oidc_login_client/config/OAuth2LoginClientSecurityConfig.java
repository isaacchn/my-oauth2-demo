package me.isaac.oidc_login_client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity(debug = true)
public class OAuth2LoginClientSecurityConfig {
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
                .oauth2Login(withDefaults());
        return http.build();
    }
}
