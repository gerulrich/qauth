package quantum.auth.model;

import io.quarkus.mongodb.panache.common.MongoEntity;
import io.quarkus.mongodb.panache.PanacheMongoEntity;

import java.util.List;

/// User account stored in the MongoDB `users` collection.
///
/// Contains profile information, authentication data, and authorization attributes.
/// The MongoDB identifier is inherited from [PanacheMongoEntity].
@MongoEntity(collection = "users")
public class User extends PanacheMongoEntity {
    /// User's display name.
    public String name;

    /// Email address used to identify the account during authentication.
    public String email;

    /// Encoded password hash used for password-based authentication, not a plaintext password.
    public String password;

    /// URL of the user's profile picture.
    public String picture;

    /// Roles assigned to the user for authorization.
    public List<String> roles;

    /// Whether the account is enabled for authentication.
    public boolean enabled;

    /// Plan associated with the account.
    public String plan;
}