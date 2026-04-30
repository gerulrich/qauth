package quantum.auth.repository;

import io.quarkus.mongodb.panache.reactive.ReactivePanacheMongoRepository;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import quantum.auth.model.User;

@ApplicationScoped
public class UserRepository implements ReactivePanacheMongoRepository<User> {

    public Uni<User> findByEmail(String email) {
        return find("email", email).firstResult();
    }
}

