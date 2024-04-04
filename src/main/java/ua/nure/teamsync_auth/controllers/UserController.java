package ua.nure.teamsync_auth.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import ua.nure.teamsync_auth.entity.User;
import ua.nure.teamsync_auth.payload.RegistrationRequest;
import ua.nure.teamsync_auth.repo.UserRepository;

@RestController
public class UserController {
    @Autowired
    public UserRepository userRepository;
    @Autowired
    public PasswordEncoder passwordEncoder;

    @PostMapping(path = "/register")
    public ResponseEntity<?> registerUser(@RequestBody(required = false) RegistrationRequest registration) {
        User entity = new User();
        entity.setUsername(registration.getLogin());
        entity.setPassword(passwordEncoder.encode(registration.getPassword()));
        entity.setRole(registration.getRole());
        userRepository.save(entity);
        return ResponseEntity.ok(userRepository.findByUsername(registration.getLogin()));
    }
}
