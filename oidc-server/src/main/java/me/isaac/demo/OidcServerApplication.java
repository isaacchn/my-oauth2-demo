package me.isaac.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(exclude = {org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class})
public class OidcServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(OidcServerApplication.class);
    }
}
