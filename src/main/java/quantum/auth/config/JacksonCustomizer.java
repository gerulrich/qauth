package quantum.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import io.quarkus.jackson.ObjectMapperCustomizer;
import jakarta.inject.Singleton;

/// Configures Jackson to use **snake_case** for JSON property names.
///
/// Java properties such as `refreshToken` map to JSON properties such as `refresh_token`
/// during serialization and deserialization.
@Singleton
public class JacksonCustomizer implements ObjectMapperCustomizer {

    /// Applies the **snake_case** naming strategy to the application object mapper.
    ///
    /// @param mapper object mapper managed by Quarkus
    @Override
    public void customize(ObjectMapper mapper) {
        mapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    }
}
