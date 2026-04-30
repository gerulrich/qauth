package quantum.auth.service;

import io.quarkus.security.UnauthorizedException;
import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import quantum.auth.api.TokenResponse;
import quantum.auth.model.User;
import quantum.auth.repository.UserRepository;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
class AuthTokenServiceTest {

    private static final String RAW_PASSWORD = "secret";

    @Inject
    AuthTokenService authTokenService;

    @Inject
    PasswordService passwordService;

    @InjectMock
    UserRepository userRepository;

    @Test
    void shouldThrowUnauthorizedWhenUserNotFound() {
        Mockito.when(userRepository.findByEmail("unknown@example.com"))
               .thenReturn(Uni.createFrom().nullItem());

        assertThrows(UnauthorizedException.class, () ->
            authTokenService.generateToken("unknown@example.com", RAW_PASSWORD).await().indefinitely()
        );
    }

    @Test
    void shouldThrowUnauthorizedWhenUserIsDisabled() {
        User user = new User();
        user.email = "disabled@example.com";
        user.enabled = false;
        user.password = passwordService.hash(RAW_PASSWORD);

        Mockito.when(userRepository.findByEmail("disabled@example.com"))
               .thenReturn(Uni.createFrom().item(user));

        assertThrows(UnauthorizedException.class, () ->
            authTokenService.generateToken("disabled@example.com", RAW_PASSWORD).await().indefinitely()
        );
    }

    @Test
    void shouldThrowUnauthorizedWhenPasswordIsWrong() {
        User user = new User();
        user.email = "active@example.com";
        user.enabled = true;
        user.plan = "pro";
        user.roles = List.of("user");
        user.password = passwordService.hash(RAW_PASSWORD);

        Mockito.when(userRepository.findByEmail("active@example.com"))
               .thenReturn(Uni.createFrom().item(user));

        assertThrows(UnauthorizedException.class, () ->
            authTokenService.generateToken("active@example.com", "wrongpassword").await().indefinitely()
        );
    }

    @Test
    void shouldReturnTokenWhenCredentialsAreValid() {
        User user = new User();
        user.email = "active@example.com";
        user.enabled = true;
        user.plan = "pro";
        user.roles = List.of("user");
        user.password = passwordService.hash(RAW_PASSWORD);

        Mockito.when(userRepository.findByEmail("active@example.com"))
               .thenReturn(Uni.createFrom().item(user));

        TokenResponse response = authTokenService.generateToken("active@example.com", RAW_PASSWORD).await().indefinitely();

        assertNotNull(response);
        assertEquals("Bearer", response.tokenType());
        assertNotNull(response.accessToken());
        assertFalse(response.accessToken().isBlank());
        assertTrue(response.expiresIn() > 0);
    }

    @Test
    void shouldReturnTokenWithDefaultRolesWhenUserHasNoRoles() {
        User user = new User();
        user.email = "noroles@example.com";
        user.enabled = true;
        user.plan = "basic";
        user.roles = null;
        user.password = passwordService.hash(RAW_PASSWORD);

        Mockito.when(userRepository.findByEmail("noroles@example.com"))
               .thenReturn(Uni.createFrom().item(user));

        TokenResponse response = authTokenService.generateToken("noroles@example.com", RAW_PASSWORD).await().indefinitely();

        assertNotNull(response);
        assertNotNull(response.accessToken());
        assertFalse(response.accessToken().isBlank());
    }
}
