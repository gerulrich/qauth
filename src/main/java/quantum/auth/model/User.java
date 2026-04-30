package quantum.auth.model;

import io.quarkus.mongodb.panache.common.MongoEntity;
import io.quarkus.mongodb.panache.PanacheMongoEntity;

import java.util.List;

@MongoEntity(collection = "users")
public class User extends PanacheMongoEntity {
    public String name;
    public String email;
    public String password;
    public String picture;
    public List<String> roles;
    public boolean enabled;
    public String plan;
}