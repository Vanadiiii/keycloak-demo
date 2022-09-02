package me.imatveev.keycloakdemo.web;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.Token;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/v1/registrations")
@PreAuthorize("permitAll()")
@RequiredArgsConstructor
public class RegistrationController {

    @PostMapping
    public Token register(@RequestParam String username,
                          @RequestParam byte[] password) {
        log.info("register user - {}", username);

        return null;
    }
}
