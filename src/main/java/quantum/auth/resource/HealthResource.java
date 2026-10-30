package quantum.auth.resource;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.openapi.annotations.Operation;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/// Provides **liveness** and application version endpoints for operational tooling.
///
/// These endpoints are excluded from the generated OpenAPI document.
/// The liveness check does not verify database connectivity or external dependencies.
@Path("/")
public class HealthResource {

    /// Application version supplied by the `app.version` configuration property.
    @ConfigProperty(name = "app.version")
    String appVersion;

    /// Reports whether the application can handle a request to `GET /health`.
    ///
    /// @return `OK`, without checking downstream dependencies
    @GET
    @Path("/health")
    @Operation(hidden = true)
    public String health() {
        return "OK";
    }

    /// Returns deployment version information from `GET /version`.
    ///
    /// @return the configured application version as plain text
    @GET
    @Path("/version")
    @Operation(hidden = true)
    @Produces(MediaType.TEXT_PLAIN)
    public String version() {
        return appVersion;
    }

}