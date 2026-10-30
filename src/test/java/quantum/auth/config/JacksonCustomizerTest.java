package quantum.auth.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class JacksonCustomizerTest {

    @Inject
    ObjectMapper objectMapper;

    @Test
    @DisplayName("Serializes JSON property names in snake_case")
    void shouldSerializePropertyNamesWhenUsingSnakeCase() throws JsonProcessingException {
        var json = objectMapper.writeValueAsString(new Profile("Test User"));
        assertEquals("{\"display_name\":\"Test User\"}", json);
    }

    @Test
    @DisplayName("Deserializes snake_case JSON property names")
    void shouldDeserializePropertyNamesWhenUsingSnakeCase() throws JsonProcessingException {
        var profile = objectMapper.readValue("{\"display_name\":\"Test User\"}", Profile.class);
        assertEquals("Test User", profile.displayName());
    }

    public record Profile(String displayName) {}
}
