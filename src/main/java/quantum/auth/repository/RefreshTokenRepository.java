package quantum.auth.repository;

import io.quarkus.mongodb.panache.reactive.ReactivePanacheMongoRepository;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import quantum.auth.model.RefreshToken;

@ApplicationScoped
public class RefreshTokenRepository implements ReactivePanacheMongoRepository<RefreshToken> {

    public Uni<RefreshToken> findByTokenHash(String tokenHash) {
        return find("tokenHash", tokenHash).firstResult();
    }
}

