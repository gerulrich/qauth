package quantum.auth.resource;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/**
 * Resource providing health check and version information endpoints.
 * <p>
 * This resource offers simple REST endpoints to verify application health status
 * and to retrieve the current version of the application. These endpoints are typically
 * used by monitoring systems, load balancers, and deployment pipelines to verify
 * the system's operational status.
 * </p>
 * <p>
 * The health endpoint returns a simple status string, while the version endpoint
 * returns the application version configured via microprofile config properties.
 * </p>
 */
@Path("/")
public class HealthResource {

    /**
     * The application version retrieved from configuration properties.
     */
    @ConfigProperty(name = "app.version")
    String appVersion;

    /**
     * Health check endpoint that verifies the application is running.
     * <p>
     * This endpoint returns a simple "OK" string when the application is operational.
     * It can be used by monitoring systems and load balancers to determine if the
     * service is healthy and available to handle requests.
     * </p>
     *
     * @return The string "OK" indicating the application is running properly
     */
    @GET
    @Path("/health")
    public String health() {
        return "OK";
    }

    /**
     * Version information endpoint.
     * <p>
     * Returns the current version of the application as defined in the configuration.
     * This endpoint is useful for verification during deployment pipelines and for
     * support teams to identify which version is running in a specific environment.
     * </p>
     *
     * @return The application version string from configuration properties
     */
    @GET
    @Path("/version")
    @Produces(MediaType.TEXT_PLAIN)
    @Operation(
        summary = "Get application version",
        description = "Returns the current version of the application"
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Version retrieved successfully",
            content = @Content(mediaType = MediaType.TEXT_PLAIN, schema = @Schema(implementation = String.class))
        )
    })
    public String version() {
        return appVersion;
    }

}