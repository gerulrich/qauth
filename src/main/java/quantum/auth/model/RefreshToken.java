package quantum.auth.model;

import io.quarkus.mongodb.panache.common.MongoEntity;
import io.quarkus.mongodb.panache.PanacheMongoEntity;

import java.time.Instant;

/// Persisted metadata for an **opaque refresh token**, stored in `refresh_tokens`.
///
/// Only the token hash is stored; the raw token is returned to the client.
/// The MongoDB identifier is inherited from [PanacheMongoEntity].
@MongoEntity(collection = "refresh_tokens")
public class RefreshToken extends PanacheMongoEntity {
    /// Hash of the raw refresh token, used to look up its persisted metadata.
    public String tokenHash;

    /// Email address of the user account associated with the token.
    public String email;

    /// Instant at which the token expires.
    public Instant expiresAt;

    /// Whether the token has been revoked, including after refresh token rotation.
    public boolean revoked;

    /// Instant at which the token was created.
    public Instant createdAt;
}
