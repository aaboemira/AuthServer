package com.Ecommerce.authserver.security.Controllers;

import org.springframework.web.bind.annotation.*;

import java.security.Principal;
@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600)
@RestController
@RequestMapping("/oauth2")
public class AuthController {
    @RequestMapping(value = "/username", method = RequestMethod.GET)
    @ResponseBody
    public String currentUserName(Principal principal) {
        return principal.getName();
    }

}
