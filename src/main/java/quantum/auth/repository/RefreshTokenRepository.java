package quantum.auth.repository;

import io.quarkus.mongodb.panache.reactive.ReactivePanacheMongoRepository;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import quantum.auth.model.RefreshToken;

/// Provides **reactive MongoDB access** to persisted refresh token metadata.
///
/// Standard persistence operations are inherited from [ReactivePanacheMongoRepository].
@ApplicationScoped
public class RefreshTokenRepository implements ReactivePanacheMongoRepository<RefreshToken> {

    /// Finds the first refresh token record matching the given hash.
    ///
    /// This lookup does not check whether the token is expired or revoked.
    ///
    /// @param tokenHash hash of the raw refresh token
    /// @return a `Uni` emitting the matching record, or `null` if no record matches
    public Uni<RefreshToken> findByTokenHash(String tokenHash) {
        return find("tokenHash", tokenHash).firstResult();
    }
}
