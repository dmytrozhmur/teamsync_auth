package ua.nure.teamsync_auth.configs;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import ua.nure.teamsync_auth.entity.User;
import ua.nure.teamsync_auth.repo.UserRepository;

@Configuration
public class ApplicationConfig {
    @Bean
    public ApplicationRunner dataLoader(
            UserRepository repo, PasswordEncoder passwordEncoder) {
        return args -> repo
                .save(new User("firstAdmin", passwordEncoder.encode("Adm12345?"), "ROLE_ADMIN"));
    }
}
