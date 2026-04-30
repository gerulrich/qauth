package quantum.auth.service;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;
import quantum.auth.model.User;
import quantum.auth.repository.UserRepository;

@ApplicationScoped
public class UserService {

    private static final Logger LOG = Logger.getLogger(UserService.class);

    @Inject
    UserRepository userRepository;

    public Uni<User> getUser(String email) {
         LOG.infof("User retrieval request received for email: %s", email);
         return userRepository.findByEmail(email);
    }
}
