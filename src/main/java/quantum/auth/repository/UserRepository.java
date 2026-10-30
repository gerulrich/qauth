package quantum.auth.repository;

import io.quarkus.mongodb.panache.reactive.ReactivePanacheMongoRepository;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import quantum.auth.model.User;

/// Provides **reactive MongoDB access** to user accounts.
///
/// Standard persistence operations are inherited from [ReactivePanacheMongoRepository].
@ApplicationScoped
public class UserRepository implements ReactivePanacheMongoRepository<User> {

    /// Finds the first user account matching the given email address.
    ///
    /// This lookup does not check whether the account is enabled.
    ///
    /// @param email email address to look up
    /// @return a `Uni` emitting the matching user, or `null` if no account matches
    public Uni<User> findByEmail(String email) {
        return find("email", email).firstResult();
    }
}
