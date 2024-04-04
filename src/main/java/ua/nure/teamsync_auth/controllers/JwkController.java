package ua.nure.teamsync_auth.controllers;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import static ua.nure.teamsync_auth.utils.RsaUtil.getRsaKey;

@RestController
public class JwkController {

    @GetMapping("/.well-known/jwks.json")
    @ResponseBody
    public String getJwkSet() {
        RSAKey rsaKey = getRsaKey();
        JWKSet jwkSet = new JWKSet(rsaKey);

        return jwkSet.toString();
    }
}

