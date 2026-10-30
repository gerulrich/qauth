package quantum.auth.service;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PasswordServiceTest {

    private final PasswordService passwordService = new PasswordService();

    @Test
    void shouldReturnPhcFormatWhenHashingPassword() {
        String hash = passwordService.hash("secret");

        assertTrue(hash.matches(
                "\\$argon2id\\$v=19\\$m=4096,t=2,p=1\\$[A-Za-z0-9+/]{22}\\$[A-Za-z0-9+/]{43}"));
        String[] parts = hash.split("\\$");
        assertEquals(16, Base64.getDecoder().decode(parts[4]).length);
        assertEquals(32, Base64.getDecoder().decode(parts[5]).length);
    }

    @Test
    void shouldGenerateDifferentSaltsWhenHashingSamePassword() {
        String firstHash = passwordService.hash("secret");
        String secondHash = passwordService.hash("secret");

        assertNotEquals(firstHash.split("\\$")[4], secondHash.split("\\$")[4]);
        assertNotEquals(firstHash, secondHash);
        assertTrue(passwordService.verify(firstHash, "secret"));
        assertTrue(passwordService.verify(secondHash, "secret"));
    }

    @Test
    void shouldVerifyWhenPasswordMatches() {
        String hash = passwordService.hash("secret");

        assertTrue(passwordService.verify(hash, "secret"));
    }

    @Test
    void shouldRejectWhenPasswordDoesNotMatch() {
        String hash = passwordService.hash("secret");

        assertFalse(passwordService.verify(hash, "wrongpassword"));
    }

    @Test
    void shouldVerifyWhenHashingCharArrayDirectly() {
        String hash = passwordService.hashArgon2("secret".toCharArray());

        assertTrue(PasswordService.verifyHashArgon2(hash, "secret"));
    }

    @Test
    void shouldVerifyWhenPasswordContainsUnicode() {
        String password = "contrase\u00f1a-\uD83D\uDD10";
        String hash = passwordService.hash(password);

        assertTrue(passwordService.verify(hash, password));
    }

    @Test
    void shouldRejectWhenStoredHashIsMissing() {
        assertFalse(passwordService.verify(null, "secret"));
        assertFalse(passwordService.verify("", "secret"));
    }
}
