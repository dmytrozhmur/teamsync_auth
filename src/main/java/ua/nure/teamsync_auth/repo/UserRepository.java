package ua.nure.teamsync_auth.repo;

import org.springframework.data.repository.CrudRepository;
import ua.nure.teamsync_auth.entity.User;

public interface UserRepository extends CrudRepository<User, String> {
    User findByUsername(String username);
}
