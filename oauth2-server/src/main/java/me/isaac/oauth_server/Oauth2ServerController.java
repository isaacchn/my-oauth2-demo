package me.isaac.oauth_server;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class Oauth2ServerController {
    @GetMapping("/")
    public ModelAndView index(){
        return new ModelAndView("index");
    }

    @GetMapping("/welcome")
    public ModelAndView welcome() {
        return new ModelAndView("welcome");
    }
}
