package quantum.auth.service;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class PasswordService {

    private static final Argon2 ARGON2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    private static final int ITERATIONS   = 2;
    private static final int MEMORY_KB    = 19456;
    private static final int PARALLELISM  = 1;

    /**
     * Hashes a raw password using Argon2id.
     *
     * @param rawPassword plain text password
     * @return Argon2id hash string
     */
    public String hash(String rawPassword) {
        return ARGON2.hash(ITERATIONS, MEMORY_KB, PARALLELISM, rawPassword.toCharArray());
    }

    /**
     * Verifies a raw password against a stored Argon2id hash.
     *
     * @param hash        stored hash
     * @param rawPassword plain text password to verify
     * @return true if the password matches the hash
     */
    public boolean verify(String hash, String rawPassword) {
        if (hash == null || hash.isEmpty()) {
            return false;
        }
        return ARGON2.verify(hash, rawPassword.toCharArray());
    }
}

