package me.isaac.oauth_client;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

@RestController
public class Oauth2ClientController {
    @GetMapping("/welcome")
    public ModelAndView welcome() {
        return new ModelAndView("welcome");
    }

    @GetMapping("/api/user")
    @PreAuthorize("hasAuthority('USER')")
    public Map<String, Object> apiUser() {
        return new HashMap<String, Object>();
    }

    @GetMapping("/api/admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    public Map<String, Object> apiAdmin() {
        return new HashMap<String, Object>();
    }

    @GetMapping("/api/root")
    @PreAuthorize("hasAuthority('ROOT')")
    public Map<String, Object> apiRoot() {
        return new HashMap<String, Object>();
    }
}
