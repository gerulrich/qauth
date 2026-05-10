package quantum.auth.service;

import io.quarkus.security.UnauthorizedException;
import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.helpers.test.UniAssertSubscriber;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import quantum.auth.model.RefreshToken;
import quantum.auth.model.User;
import quantum.auth.repository.RefreshTokenRepository;
import quantum.auth.repository.UserRepository;

import java.time.Instant;
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

    @InjectMock
    RefreshTokenRepository refreshTokenRepository;

    @InjectMock
    GoogleTokenVerifierService googleTokenVerifierService;

    // ---------------------------------------------------
    // generateToken
    // ---------------------------------------------------

    @Test
    void shouldThrowUnauthorizedWhenUserNotFound() {
        Mockito.when(userRepository.findByEmail("unknown@example.com"))
               .thenReturn(Uni.createFrom().nullItem());

        authTokenService.generateToken("unknown@example.com", RAW_PASSWORD)
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }

    @Test
    void shouldThrowUnauthorizedWhenUserIsDisabled() {
        User user = new User();
        user.email = "disabled@example.com";
        user.enabled = false;
        user.password = passwordService.hash(RAW_PASSWORD);

        Mockito.when(userRepository.findByEmail("disabled@example.com"))
               .thenReturn(Uni.createFrom().item(user));

        authTokenService.generateToken("disabled@example.com", RAW_PASSWORD)
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
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

        authTokenService.generateToken("active@example.com", "wrongpassword")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
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
        Mockito.when(refreshTokenRepository.persist(Mockito.<RefreshToken>any()))
               .thenAnswer(inv -> { RefreshToken rt = inv.getArgument(0); return Uni.createFrom().item(rt); });

        var response = authTokenService.generateToken("active@example.com", RAW_PASSWORD)
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitItem()
            .assertCompleted()
            .getItem();

        assertNotNull(response);
        assertEquals("Bearer", response.tokenType());
        assertNotNull(response.accessToken());
        assertFalse(response.accessToken().isBlank());
        assertNotNull(response.refreshToken());
        assertFalse(response.refreshToken().isBlank());
        assertTrue(response.expiresIn() > 0);
        assertTrue(response.refreshExpiresIn() > 0);
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
        Mockito.when(refreshTokenRepository.persist(Mockito.<RefreshToken>any()))
               .thenAnswer(inv -> { RefreshToken rt = inv.getArgument(0); return Uni.createFrom().item(rt); });

        var response = authTokenService.generateToken("noroles@example.com", RAW_PASSWORD)
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitItem()
            .assertCompleted()
            .getItem();

        assertNotNull(response);
        assertNotNull(response.accessToken());
        assertFalse(response.accessToken().isBlank());
    }

    @Test
    void shouldReturnTokenWhenGoogleTokenIsValid() {
        User user = new User();
        user.email = "google-active@example.com";
        user.enabled = true;
        user.plan = "pro";
        user.roles = List.of("user");

        Mockito.when(googleTokenVerifierService.verifyAndExtractEmail("valid-google-token"))
               .thenReturn(Uni.createFrom().item("google-active@example.com"));
        Mockito.when(userRepository.findByEmail("google-active@example.com"))
               .thenReturn(Uni.createFrom().item(user));
        Mockito.when(refreshTokenRepository.persist(Mockito.<RefreshToken>any()))
               .thenAnswer(inv -> { RefreshToken rt = inv.getArgument(0); return Uni.createFrom().item(rt); });

        var response = authTokenService.generateTokenFromGoogle("valid-google-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitItem()
            .assertCompleted()
            .getItem();

        assertNotNull(response);
        assertEquals("Bearer", response.tokenType());
        assertNotNull(response.accessToken());
        assertFalse(response.accessToken().isBlank());
        assertNotNull(response.refreshToken());
        assertFalse(response.refreshToken().isBlank());
    }

    @Test
    void shouldThrowUnauthorizedWhenGoogleUserNotFound() {
        Mockito.when(googleTokenVerifierService.verifyAndExtractEmail("valid-google-token"))
               .thenReturn(Uni.createFrom().item("missing-google@example.com"));
        Mockito.when(userRepository.findByEmail("missing-google@example.com"))
               .thenReturn(Uni.createFrom().nullItem());

        authTokenService.generateTokenFromGoogle("valid-google-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }

    @Test
    void shouldThrowUnauthorizedWhenGoogleUserIsDisabled() {
        User user = new User();
        user.email = "disabled-google@example.com";
        user.enabled = false;

        Mockito.when(googleTokenVerifierService.verifyAndExtractEmail("valid-google-token"))
               .thenReturn(Uni.createFrom().item("disabled-google@example.com"));
        Mockito.when(userRepository.findByEmail("disabled-google@example.com"))
               .thenReturn(Uni.createFrom().item(user));

        authTokenService.generateTokenFromGoogle("valid-google-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }

    @Test
    void shouldThrowUnauthorizedWhenGoogleTokenIsInvalid() {
        Mockito.when(googleTokenVerifierService.verifyAndExtractEmail("invalid-google-token"))
               .thenReturn(Uni.createFrom().failure(new UnauthorizedException("Authorization header is invalid or has been expired")));

        authTokenService.generateTokenFromGoogle("invalid-google-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }

    // ---------------------------------------------------
    // refreshToken (opaque refresh token)
    // ---------------------------------------------------

    @Test
    void shouldIssueNewTokensWhenRefreshTokenIsValid() {
        User user = new User();
        user.email = "refresh@example.com";
        user.enabled = true;
        user.plan = "pro";
        user.roles = List.of("user");

        RefreshToken stored = new RefreshToken();
        stored.email = "refresh@example.com";
        stored.revoked = false;
        stored.expiresAt = Instant.now().plusSeconds(3600);

        Mockito.when(refreshTokenRepository.findByTokenHash(Mockito.anyString()))
               .thenReturn(Uni.createFrom().item(stored));
        Mockito.when(refreshTokenRepository.persistOrUpdate(Mockito.<RefreshToken>any()))
               .thenAnswer(inv -> { RefreshToken rt = inv.getArgument(0); return Uni.createFrom().item(rt); });
        Mockito.when(userRepository.findByEmail("refresh@example.com"))
               .thenReturn(Uni.createFrom().item(user));
        Mockito.when(refreshTokenRepository.persist(Mockito.<RefreshToken>any()))
               .thenAnswer(inv -> { RefreshToken rt = inv.getArgument(0); return Uni.createFrom().item(rt); });

        var response = authTokenService.refreshToken("any-raw-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitItem()
            .assertCompleted()
            .getItem();

        assertNotNull(response);
        assertEquals("Bearer", response.tokenType());
        assertNotNull(response.accessToken());
        assertNotNull(response.refreshToken());
        assertFalse(response.refreshToken().isBlank());
    }

    @Test
    void shouldThrowUnauthorizedWhenRefreshTokenIsRevoked() {
        RefreshToken stored = new RefreshToken();
        stored.email = "refresh@example.com";
        stored.revoked = true;
        stored.expiresAt = Instant.now().plusSeconds(3600);

        Mockito.when(refreshTokenRepository.findByTokenHash(Mockito.anyString()))
               .thenReturn(Uni.createFrom().item(stored));

        authTokenService.refreshToken("any-raw-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }

    @Test
    void shouldThrowUnauthorizedWhenRefreshTokenIsExpired() {
        RefreshToken stored = new RefreshToken();
        stored.email = "refresh@example.com";
        stored.revoked = false;
        stored.expiresAt = Instant.now().minusSeconds(1);

        Mockito.when(refreshTokenRepository.findByTokenHash(Mockito.anyString()))
               .thenReturn(Uni.createFrom().item(stored));

        authTokenService.refreshToken("any-raw-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }

    @Test
    void shouldThrowUnauthorizedWhenRefreshTokenNotFound() {
        Mockito.when(refreshTokenRepository.findByTokenHash(Mockito.anyString()))
               .thenReturn(Uni.createFrom().nullItem());

        authTokenService.refreshToken("any-raw-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }
}
