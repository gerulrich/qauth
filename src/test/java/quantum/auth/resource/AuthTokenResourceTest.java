package quantum.auth.resource;

import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mockito;
import quantum.auth.model.RefreshToken;
import quantum.auth.model.User;
import quantum.auth.repository.RefreshTokenRepository;
import quantum.auth.repository.UserRepository;
import quantum.auth.service.TokenVerifierService;
import quantum.auth.service.PasswordService;
import quantum.auth.service.GoogleTokenVerifier;
import quantum.auth.service.OidcTokenVerifier;

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
    @GoogleTokenVerifier
    TokenVerifierService tokenVerifierService;

    @InjectMock
    @OidcTokenVerifier
    TokenVerifierService oidcTokenVerifierService;

    @Test
    @DisplayName("Documents authentication endpoints and excludes operational endpoints from OpenAPI")
    void shouldDocumentAuthenticationEndpointsWithoutOperationalEndpoints() {
        given()
            .accept(ContentType.JSON)
            .when().get("/q/openapi")
            .then()
            .statusCode(200)
            .body("paths", hasKey("/auth/token"))
            .body("paths", hasKey("/auth/token/google"))
            .body("paths", hasKey("/auth/token/oidc"))
            .body("paths", hasKey("/auth/refresh"))
            .body("paths", hasKey("/auth/me"))
            .body("paths", not(hasKey("/health")))
            .body("paths", not(hasKey("/version")))
            .body("paths.'/auth/refresh'.post.responses", hasKey("400"))
            .body("paths.'/auth/token'.post.requestBody.required", is(true))
            .body("paths.'/auth/me'.get.security[0]", hasKey("bearerAuth"))
            .body("components.securitySchemes.bearerAuth.type", is("http"))
            .body("components.securitySchemes.bearerAuth.scheme", is("bearer"));
    }

    @Test
    @DisplayName("Returns HTTP 400 for an empty credentials payload")
    void shouldReturnBadRequestWhenBodyIsEmpty() {
        given()
            .contentType(ContentType.JSON)
            .body("{}")
            .when().post("/auth/token")
            .then()
            .statusCode(400);
    }

    @Test
    @DisplayName("Returns HTTP 400 when the email is blank")
    void shouldReturnBadRequestWhenEmailIsBlank() {
        given()
            .contentType(ContentType.JSON)
            .body("{\"email\":\"\",\"password\":\"secret\"}")
            .when().post("/auth/token")
            .then()
            .statusCode(400);
    }

    @Test
    @DisplayName("Returns HTTP 400 when the password is blank")
    void shouldReturnBadRequestWhenPasswordIsBlank() {
        given()
            .contentType(ContentType.JSON)
            .body("{\"email\":\"user@example.com\",\"password\":\"\"}")
            .when().post("/auth/token")
            .then()
            .statusCode(400);
    }

    @Test
    @DisplayName("Returns HTTP 401 for an unknown user")
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
    @DisplayName("Returns HTTP 401 for a disabled account")
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
    @DisplayName("Returns tokens when user credentials are valid")
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
    @DisplayName("Returns tokens with default roles when the user has no roles")
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
    @DisplayName("Returns HTTP 400 for an empty Google sign-in payload")
    void shouldReturnBadRequestWhenGoogleTokenBodyIsEmpty() {
        given()
            .contentType(ContentType.JSON)
            .body("{}")
            .when().post("/auth/token/google")
            .then()
            .statusCode(400);
    }

    @Test
    @DisplayName("Returns HTTP 401 for an invalid Google ID token")
    void shouldReturnUnauthorizedWhenGoogleTokenIsInvalid() {
        Mockito.when(tokenVerifierService.verifyAndExtractEmail("invalid-google-token"))
               .thenReturn(Uni.createFrom().failure(new io.quarkus.security.UnauthorizedException("Authorization header is invalid or has been expired")));

        given()
            .contentType(ContentType.JSON)
            .body("{\"token\":\"invalid-google-token\"}")
            .when().post("/auth/token/google")
            .then()
            .statusCode(401);
    }

    @Test
    @DisplayName("Returns application tokens for a valid Google ID token")
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
    @DisplayName("Returns HTTP 401 when the Google account user is disabled")
    void shouldReturnUnauthorizedWhenGoogleUserIsDisabled() {
        User user = new User();
        user.email = "google-disabled@example.com";
        user.enabled = false;

        Mockito.when(tokenVerifierService.verifyAndExtractEmail("valid-google-token"))
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
    @DisplayName("Returns HTTP 400 for an empty OIDC sign-in payload")
    void shouldReturnBadRequestWhenOidcTokenBodyIsEmpty() {
        given()
            .contentType(ContentType.JSON)
            .body("{}")
            .when().post("/auth/token/oidc")
            .then()
            .statusCode(400);
    }

    @Test
    @DisplayName("Returns HTTP 401 for an invalid OIDC ID token")
    void shouldReturnUnauthorizedWhenOidcTokenIsInvalid() {
        Mockito.when(oidcTokenVerifierService.verifyAndExtractEmail("invalid-oidc-token"))
               .thenReturn(Uni.createFrom().failure(new io.quarkus.security.UnauthorizedException("Authorization header is invalid or has been expired")));

        given()
            .contentType(ContentType.JSON)
            .body("{\"token\":\"invalid-oidc-token\"}")
            .when().post("/auth/token/oidc")
            .then()
            .statusCode(401);
    }

    @Test
    @DisplayName("Returns application tokens for a valid OIDC ID token")
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

        given()
            .contentType(ContentType.JSON)
            .body("{\"token\":\"valid-oidc-token\"}")
            .when().post("/auth/token/oidc")
            .then()
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            .body("access_token", notNullValue())
            .body("refresh_token", notNullValue())
            .body("expires_in", greaterThan(0));
    }

    @Test
    @DisplayName("Returns HTTP 401 when the OIDC account user is disabled")
    void shouldReturnUnauthorizedWhenOidcUserIsDisabled() {
        User user = new User();
        user.email = "oidc-disabled@example.com";
        user.enabled = false;

        Mockito.when(oidcTokenVerifierService.verifyAndExtractEmail("valid-oidc-token"))
               .thenReturn(Uni.createFrom().item("oidc-disabled@example.com"));
        Mockito.when(userRepository.findByEmail("oidc-disabled@example.com"))
               .thenReturn(Uni.createFrom().item(user));

        given()
            .contentType(ContentType.JSON)
            .body("{\"token\":\"valid-oidc-token\"}")
            .when().post("/auth/token/oidc")
            .then()
            .statusCode(401);
    }

    @Test
    @DisplayName("Returns HTTP 400 for an empty refresh token payload")
    void shouldReturnBadRequestWhenRefreshBodyIsEmpty() {
        given()
            .contentType(ContentType.JSON)
            .body("{}")
            .when().post("/auth/refresh")
            .then()
            .statusCode(400);
    }

    @Test
    @DisplayName("Returns HTTP 401 for an unknown refresh token")
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
    @DisplayName("Returns HTTP 401 for a revoked refresh token")
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
    @DisplayName("Returns HTTP 401 for an expired refresh token")
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
    @DisplayName("Returns new tokens when the refresh token is valid")
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
