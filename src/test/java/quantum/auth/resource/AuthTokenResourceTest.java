package quantum.auth.resource;

import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import quantum.auth.model.User;
import quantum.auth.repository.UserRepository;
import quantum.auth.service.PasswordService;

import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

@QuarkusTest
class AuthTokenResourceTest {

    @Inject
    PasswordService passwordService;

    @InjectMock
    UserRepository userRepository;

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

        given()
            .contentType(ContentType.JSON)
            .body("{\"email\":\"active@example.com\",\"password\":\"secret\"}")
            .when().post("/auth/token")
            .then()
            .statusCode(200)
            .body("token_type", equalTo("Bearer"))
            .body("access_token", notNullValue())
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

        given()
            .contentType(ContentType.JSON)
            .body("{\"email\":\"noroles@example.com\",\"password\":\"secret\"}")
            .when().post("/auth/token")
            .then()
            .statusCode(200)
            .body("access_token", notNullValue());
    }
}
