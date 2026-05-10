package quantum.auth.model;

import io.quarkus.mongodb.panache.common.MongoEntity;
import io.quarkus.mongodb.panache.PanacheMongoEntity;

import java.time.Instant;

@MongoEntity(collection = "refresh_tokens")
public class RefreshToken extends PanacheMongoEntity {
    public String tokenHash;
    public String email;
    public Instant expiresAt;
    public boolean revoked;
    public Instant createdAt;
}

