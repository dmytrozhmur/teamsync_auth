package ua.nure.teamsync_auth.enhancer;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import ua.nure.teamsync_auth.entity.User;

import java.util.Map;


public class TokenRoleEnhancer extends JwtAccessTokenConverter {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
        DefaultOAuth2AccessToken tokenToUpdate = (DefaultOAuth2AccessToken) oAuth2AccessToken;
        tokenToUpdate.getAdditionalInformation().put("role", ((User) oAuth2Authentication.getPrincipal()).getAuthorities());
        return tokenToUpdate;
    }
}
