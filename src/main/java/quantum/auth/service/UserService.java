package quantum.auth.service;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;
import quantum.auth.model.User;
import quantum.auth.repository.UserRepository;

/// Provides **reactive user account retrieval** through [UserRepository].
@ApplicationScoped
public class UserService {

    private static final Logger LOG = Logger.getLogger(UserService.class);

    @Inject
    UserRepository userRepository;

    /// Retrieves a user account by email address and logs the lookup request.
    ///
    /// This lookup does not check whether the account is enabled.
    ///
    /// @param email email address identifying the account
    /// @return a `Uni` emitting the matching user, or `null` if no account matches
    public Uni<User> getUser(String email) {
         LOG.infof("User retrieval request received for email: %s", email);
         return userRepository.findByEmail(email);
    }
}
