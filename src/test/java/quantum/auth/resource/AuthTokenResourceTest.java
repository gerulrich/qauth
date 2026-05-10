package quantum.auth.resource;

import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import quantum.auth.model.RefreshToken;
import quantum.auth.model.User;
import quantum.auth.repository.RefreshTokenRepository;
import quantum.auth.repository.UserRepository;
import quantum.auth.service.GoogleTokenVerifierService;
import quantum.auth.service.PasswordService;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

@QuarkusTest
class AuthTokenResourceTest {

    @Inject
    PasswordService passwordService;

    @InjectMock
    UserRepository userRepository;

    @InjectMock
    RefreshTokenRepository refreshTokenRepository;

    @InjectMock
    GoogleTokenVerifierService googleTokenVerifierService;

    @Test
    void shouldReturnBadRequestWhenBodyIsEmpty() {
        given()
            .contentType(ContentType.JSON)
            .body("{}")
            .when().post("/auth/token")
            .then()
            .statusCode(400);
    }

    @Test
    void shouldReturnBadRequestWhenEmailIsBlank() {
        given()
            .contentType(ContentType.JSON)
            .body("{\"email\":\"\",\"password\":\"secret\"}")
            .when().post("/auth/token")
            .then()
            .statusCode(400);
    }

    @Test
    void shouldReturnBadRequestWhenPasswordIsBlank() {
        given()
            .contentType(ContentType.JSON)
            .body("{\"email\":\"user@example.com\",\"password\":\"\"}")
            .when().post("/auth/token")
            .then()
            .statusCode(400);
    }

    @Test
    void shouldReturnUnauthorizedWhenUserNotFound() {
        Mockito.when(userRepository.findByEmail("unknown@example.com"))
               .thenReturn(Uni.createFrom().nullItem());

        given()
            .contentType(ContentType.JSON)
            .body("{\"email\":\"unknown@example.com\",\"password\":\"secret\"}")
            .when().post("/auth/token")
            .then()
            .statusCode(401);
    }

    @Test
    void shouldReturnUnauthorizedWhenUserIsDisabled() {
        User user = new User();
        user.email = "disabled@example.com";
        user.enabled = false;

        Mockito.when(userRepository.findByEmail("disabled@example.com"))
               .thenReturn(Uni.createFrom().item(user));

        given()
            .contentType(ContentType.JSON)
            .body("{\"email\":\"disabled@example.com\",\"password\":\"secret\"}")
            .when().post("/auth/token")
            .then()
            .statusCode(401);
    }

    @Test
    void shouldReturnTokenWhenUserIsValid() {
        String password = "secret";
        User user = new User();
        user.email = "active@example.com";
        user.password = passwordService.hash(password);
        user.enabled = true;
        user.plan = "pro";
        user.roles = List.of("user");

        Mockito.when(userRepository.findByEmail("active@example.com"))
               .thenReturn(Uni.createFrom().item(user));
        Mockito.when(refreshTokenRepository.persist(Mockito.<RefreshToken>any()))
               .thenAnswer(inv -> { RefreshToken rt = inv.getArgument(0); return Uni.createFrom().item(rt); });

        given()
            .contentType(ContentType.JSON)
            .body("{\"email\":\"active@example.com\",\"password\":\"secret\"}")
            .when().post("/auth/token")
            .then()
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            .body("access_token", notNullValue())
            .body("refresh_token", notNullValue())
            .body("expires_in", greaterThan(0));
    }


    @Test
    void shouldReturnTokenWithDefaultRolesWhenUserHasNoRoles() {
        String password = "secret";
        User user = new User();
        user.email = "noroles@example.com";
        user.password = passwordService.hash(password);
        user.enabled = true;
        user.plan = "basic";
        user.roles = null;

        Mockito.when(userRepository.findByEmail("noroles@example.com"))
               .thenReturn(Uni.createFrom().item(user));
        Mockito.when(refreshTokenRepository.persist(Mockito.<RefreshToken>any()))
               .thenAnswer(inv -> { RefreshToken rt = inv.getArgument(0); return Uni.createFrom().item(rt); });

        given()
            .contentType(ContentType.JSON)
            .body("{\"email\":\"noroles@example.com\",\"password\":\"secret\"}")
            .when().post("/auth/token")
            .then()
            .statusCode(200)
            .body("access_token", notNullValue());
    }

    @Test
    void shouldReturnBadRequestWhenGoogleTokenBodyIsEmpty() {
        given()
            .contentType(ContentType.JSON)
            .body("{}")
            .when().post("/auth/token/google")
            .then()
            .statusCode(400);
    }

    @Test
    void shouldReturnUnauthorizedWhenGoogleTokenIsInvalid() {
        Mockito.when(googleTokenVerifierService.verifyAndExtractEmail("invalid-google-token"))
               .thenReturn(Uni.createFrom().failure(new io.quarkus.security.UnauthorizedException("Authorization header is invalid or has been expired")));

        given()
            .contentType(ContentType.JSON)
            .body("{\"token\":\"invalid-google-token\"}")
            .when().post("/auth/token/google")
            .then()
            .statusCode(401);
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

        given()
            .contentType(ContentType.JSON)
            .body("{\"token\":\"valid-google-token\"}")
            .when().post("/auth/token/google")
            .then()
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            .body("access_token", notNullValue())
            .body("refresh_token", notNullValue())
            .body("expires_in", greaterThan(0));
    }

    @Test
    void shouldReturnUnauthorizedWhenGoogleUserIsDisabled() {
        User user = new User();
        user.email = "google-disabled@example.com";
        user.enabled = false;

        Mockito.when(googleTokenVerifierService.verifyAndExtractEmail("valid-google-token"))
               .thenReturn(Uni.createFrom().item("google-disabled@example.com"));
        Mockito.when(userRepository.findByEmail("google-disabled@example.com"))
               .thenReturn(Uni.createFrom().item(user));

        given()
            .contentType(ContentType.JSON)
            .body("{\"token\":\"valid-google-token\"}")
            .when().post("/auth/token/google")
            .then()
            .statusCode(401);
    }

    @Test
    void shouldReturnBadRequestWhenRefreshBodyIsEmpty() {
        given()
            .contentType(ContentType.JSON)
            .body("{}")
            .when().post("/auth/refresh")
            .then()
            .statusCode(400);
    }

    @Test
    void shouldReturnUnauthorizedWhenRefreshTokenNotFound() {
        String rawRefreshToken = "missing-token";

        Mockito.when(refreshTokenRepository.findByTokenHash(sha256Hex(rawRefreshToken)))
               .thenReturn(Uni.createFrom().nullItem());

        given()
            .contentType(ContentType.JSON)
            .body("{\"refresh_token\":\"missing-token\"}")
            .when().post("/auth/refresh")
            .then()
            .statusCode(401);
    }

    @Test
    void shouldReturnUnauthorizedWhenRefreshTokenIsRevoked() {
        String rawRefreshToken = "revoked-token";
        RefreshToken stored = new RefreshToken();
        stored.email = "revoked@example.com";
        stored.revoked = true;
        stored.expiresAt = Instant.now().plusSeconds(3600);

        Mockito.when(refreshTokenRepository.findByTokenHash(sha256Hex(rawRefreshToken)))
               .thenReturn(Uni.createFrom().item(stored));

        given()
            .contentType(ContentType.JSON)
            .body("{\"refresh_token\":\"revoked-token\"}")
            .when().post("/auth/refresh")
            .then()
            .statusCode(401);
    }

    @Test
    void shouldReturnUnauthorizedWhenRefreshTokenIsExpired() {
        String rawRefreshToken = "expired-token";
        RefreshToken stored = new RefreshToken();
        stored.email = "expired@example.com";
        stored.revoked = false;
        stored.expiresAt = Instant.now().minusSeconds(1);

        Mockito.when(refreshTokenRepository.findByTokenHash(sha256Hex(rawRefreshToken)))
               .thenReturn(Uni.createFrom().item(stored));

        given()
            .contentType(ContentType.JSON)
            .body("{\"refresh_token\":\"expired-token\"}")
            .when().post("/auth/refresh")
            .then()
            .statusCode(401);
    }

    @Test
    void shouldReturnNewTokensWhenRefreshTokenIsValid() {
        String rawRefreshToken = "valid-token";

        RefreshToken stored = new RefreshToken();
        stored.email = "refresh@example.com";
        stored.revoked = false;
        stored.expiresAt = Instant.now().plusSeconds(3600);

        User user = new User();
        user.email = "refresh@example.com";
        user.enabled = true;
        user.plan = "pro";
        user.roles = List.of("user");

        Mockito.when(refreshTokenRepository.findByTokenHash(sha256Hex(rawRefreshToken)))
               .thenReturn(Uni.createFrom().item(stored));
        Mockito.when(refreshTokenRepository.persistOrUpdate(Mockito.<RefreshToken>any()))
               .thenAnswer(inv -> {
                   RefreshToken rt = inv.getArgument(0);
                   return Uni.createFrom().item(rt);
               });
        Mockito.when(userRepository.findByEmail("refresh@example.com"))
               .thenReturn(Uni.createFrom().item(user));
        Mockito.when(refreshTokenRepository.persist(Mockito.<RefreshToken>any()))
               .thenAnswer(inv -> {
                   RefreshToken rt = inv.getArgument(0);
                   return Uni.createFrom().item(rt);
               });

        given()
            .contentType(ContentType.JSON)
            .body("{\"refresh_token\":\"valid-token\"}")
            .when().post("/auth/refresh")
            .then()
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            .body("access_token", notNullValue())
            .body("refresh_token", notNullValue())
            .body("expires_in", greaterThan(0))
            .body("refresh_expires_in", greaterThan(0));
    }

    private static String sha256Hex(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
