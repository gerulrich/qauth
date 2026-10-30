package quantum.auth.service;

import io.quarkus.security.UnauthorizedException;
import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.helpers.test.UniAssertSubscriber;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
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
    @GoogleTokenVerifier
    TokenVerifierService tokenVerifierService;

    @InjectMock
    @OidcTokenVerifier
    TokenVerifierService oidcTokenVerifierService;

    // ---------------------------------------------------
    // generateToken
    // ---------------------------------------------------

    @Test
    @DisplayName("Rejects password authentication for an unknown user")
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
    @DisplayName("Rejects password authentication for a disabled account")
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
    @DisplayName("Rejects password authentication with an incorrect password")
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
    @DisplayName("Issues tokens when user credentials are valid")
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
    @DisplayName("Assigns default roles when the user has no roles")
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
    @DisplayName("Issues application tokens for a valid Google ID token")
    void shouldReturnTokenWhenGoogleTokenIsValid() {
        User user = new User();
        user.email = "google-active@example.com";
        user.enabled = true;
        user.plan = "pro";
        user.roles = List.of("user");

        Mockito.when(tokenVerifierService.verifyAndExtractEmail("valid-google-token"))
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
    @DisplayName("Rejects Google sign-in for an unknown user")
    void shouldThrowUnauthorizedWhenGoogleUserNotFound() {
        Mockito.when(tokenVerifierService.verifyAndExtractEmail("valid-google-token"))
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
    @DisplayName("Rejects Google sign-in for a disabled account")
    void shouldThrowUnauthorizedWhenGoogleUserIsDisabled() {
        User user = new User();
        user.email = "disabled-google@example.com";
        user.enabled = false;

        Mockito.when(tokenVerifierService.verifyAndExtractEmail("valid-google-token"))
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
    @DisplayName("Rejects Google sign-in with an invalid ID token")
    void shouldThrowUnauthorizedWhenGoogleTokenIsInvalid() {
        Mockito.when(tokenVerifierService.verifyAndExtractEmail("invalid-google-token"))
               .thenReturn(Uni.createFrom().failure(new UnauthorizedException("Authorization header is invalid or has been expired")));

        authTokenService.generateTokenFromGoogle("invalid-google-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }

    @Test
    @DisplayName("Issues application tokens for a valid OIDC ID token")
    void shouldReturnTokenWhenOidcTokenIsValid() {
        User user = new User();
        user.email = "oidc-active@example.com";
        user.enabled = true;
        user.plan = "pro";
        user.roles = List.of("user");

        Mockito.when(oidcTokenVerifierService.verifyAndExtractEmail("valid-oidc-token"))
               .thenReturn(Uni.createFrom().item("oidc-active@example.com"));
        Mockito.when(userRepository.findByEmail("oidc-active@example.com"))
               .thenReturn(Uni.createFrom().item(user));
        Mockito.when(refreshTokenRepository.persist(Mockito.<RefreshToken>any()))
               .thenAnswer(inv -> { RefreshToken rt = inv.getArgument(0); return Uni.createFrom().item(rt); });

        var response = authTokenService.generateTokenFromOidc("valid-oidc-token")
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
    @DisplayName("Rejects OIDC sign-in for an unknown user")
    void shouldThrowUnauthorizedWhenOidcUserNotFound() {
        Mockito.when(oidcTokenVerifierService.verifyAndExtractEmail("valid-oidc-token"))
               .thenReturn(Uni.createFrom().item("missing-oidc@example.com"));
        Mockito.when(userRepository.findByEmail("missing-oidc@example.com"))
               .thenReturn(Uni.createFrom().nullItem());

        authTokenService.generateTokenFromOidc("valid-oidc-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }

    @Test
    @DisplayName("Rejects OIDC sign-in for a disabled account")
    void shouldThrowUnauthorizedWhenOidcUserIsDisabled() {
        User user = new User();
        user.email = "disabled-oidc@example.com";
        user.enabled = false;

        Mockito.when(oidcTokenVerifierService.verifyAndExtractEmail("valid-oidc-token"))
               .thenReturn(Uni.createFrom().item("disabled-oidc@example.com"));
        Mockito.when(userRepository.findByEmail("disabled-oidc@example.com"))
               .thenReturn(Uni.createFrom().item(user));

        authTokenService.generateTokenFromOidc("valid-oidc-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }

    @Test
    @DisplayName("Rejects OIDC sign-in with an invalid ID token")
    void shouldThrowUnauthorizedWhenOidcTokenIsInvalid() {
        Mockito.when(oidcTokenVerifierService.verifyAndExtractEmail("invalid-oidc-token"))
               .thenReturn(Uni.createFrom().failure(new UnauthorizedException("Authorization header is invalid or has been expired")));

        authTokenService.generateTokenFromOidc("invalid-oidc-token")
            .subscribe()
            .withSubscriber(UniAssertSubscriber.create())
            .awaitFailure()
            .assertFailedWith(UnauthorizedException.class);
    }

    // ---------------------------------------------------
    // refreshToken (opaque refresh token)
    // ---------------------------------------------------

    @Test
    @DisplayName("Rotates a valid refresh token and issues new tokens")
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
    @DisplayName("Rejects a revoked refresh token")
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
    @DisplayName("Rejects an expired refresh token")
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
    @DisplayName("Rejects an unknown refresh token")
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
