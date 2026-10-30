package quantum.auth.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PasswordServiceTest {

    public static final String ARGON2ID_HASH_PATTERN = "\\$argon2id\\$v=19\\$m=4096,t=2,p=1\\$[A-Za-z0-9+/]{22}\\$[A-Za-z0-9+/]{43}";
    private final PasswordService passwordService = new PasswordService();

    @Test
    @DisplayName("Encodes password hashes in PHC format")
    void shouldReturnPhcFormatWhenHashingPassword() {
        String hash = passwordService.hash("secret");
        assertTrue(hash.matches(ARGON2ID_HASH_PATTERN));
        String[] parts = hash.split("\\$");
        assertEquals(16, Base64.getDecoder().decode(parts[4]).length);
        assertEquals(32, Base64.getDecoder().decode(parts[5]).length);
    }

    @Test
    @DisplayName("Generates different salts for the same password")
    void shouldGenerateDifferentSaltsWhenHashingSamePassword() {
        String firstHash = passwordService.hash("secret");
        String secondHash = passwordService.hash("secret");

        assertNotEquals(firstHash.split("\\$")[4], secondHash.split("\\$")[4]);
        assertNotEquals(firstHash, secondHash);
        assertTrue(passwordService.verify(firstHash, "secret"));
        assertTrue(passwordService.verify(secondHash, "secret"));
    }

    @Test
    @DisplayName("Accepts a password matching the stored hash")
    void shouldVerifyWhenPasswordMatches() {
        String hash = passwordService.hash("secret");
        assertTrue(passwordService.verify(hash, "secret"));
    }

    @Test
    @DisplayName("Rejects a password that does not match the stored hash")
    void shouldRejectWhenPasswordDoesNotMatch() {
        String hash = passwordService.hash("secret");
        assertFalse(passwordService.verify(hash, "wrongpassword"));
    }

    @Test
    @DisplayName("Verifies passwords containing Unicode characters")
    void shouldVerifyWhenPasswordContainsUnicode() {
        String password = "contraseña-\uD83D\uDD10";
        String hash = passwordService.hash(password);
        assertTrue(passwordService.verify(hash, password));
    }

    @Test
    @DisplayName("Rejects verification when the stored hash is missing")
    void shouldRejectWhenStoredHashIsMissing() {
        assertFalse(passwordService.verify(null, "secret"));
        assertFalse(passwordService.verify("", "secret"));
    }

    @Test
    @DisplayName("Rejects malformed or unsupported password hashes")
    void shouldRejectMalformedOrUnsupportedHash() {
        assertFalse(passwordService.verify("$argon2id$v=19$m=4096,t=2,p=1$invalid$invalid", "secret"));
        assertFalse(passwordService.verify("$argon2id$v=99$m=4096,t=2,p=1$c2FsdA$aGFzaA", "secret"));
        assertFalse(passwordService.verify("$argon2id$v=19$m=4096,m=4096,t=2,p=1$c2FsdA$aGFzaA", "secret"));
    }
}
