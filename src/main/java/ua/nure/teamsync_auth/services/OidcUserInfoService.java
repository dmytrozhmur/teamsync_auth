//package ua.nure.teamsync_auth.services;
//
//import java.util.Collections;
//import java.util.Map;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
//import org.springframework.stereotype.Service;
//import ua.nure.teamsync_auth.entity.User;
//import ua.nure.teamsync_auth.repo.UserRepository;
//
///**
// * Example service to perform lookup of user info for customizing an {@code id_token}.
// */
//@Service
//public class OidcUserInfoService {
//    @Autowired
//    private UserRepository userRepository;
//
//    public OidcUserInfo loadUser(String username) {
//        return new OidcUserInfo(getUser(username));
//    }
//
//    private Map<String, Object> getUser(String username) {
//        User user = userRepository.findByUsername(username);
//        return OidcUserInfo.builder()
//                .subject(username)
//                .claim("roles", user.getAuthorities())
//                .build()
//                .getClaims();
//    }
//}
