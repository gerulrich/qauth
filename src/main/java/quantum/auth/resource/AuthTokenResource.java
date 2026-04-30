package quantum.auth.resource;

import io.quarkus.security.Authenticated;
import io.smallrye.mutiny.Uni;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import quantum.auth.api.ApiUser;
import quantum.auth.api.TokenResponse;
import quantum.auth.api.TokenRequest;
import quantum.auth.service.AuthTokenService;
import quantum.auth.service.UserService;

@Path("/auth")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "Authentication", description = "Operations for obtaining authentication tokens")
public class AuthTokenResource {

    @Inject
    AuthTokenService authTokenService;

    @Inject
    UserService userService;

    @POST
    @Path("/token")
    @PermitAll
    @Operation(
        summary = "Generate JWT token",
        description = "Authenticates a user with email and password and returns a signed JWT Bearer token."
    )
    @RequestBody(content = @Content(schema = @Schema(implementation = TokenRequest.class)))
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Token generated successfully",
            content = @Content(schema = @Schema(implementation = TokenResponse.class))
        ),
        @APIResponse(responseCode = "401", description = "Invalid credentials"),
        @APIResponse(responseCode = "400", description = "Invalid request body")
    })
    public Uni<TokenResponse> generateToken(@Valid TokenRequest request) {
        return authTokenService.generateToken(request.email(), request.password());
    }

    @GET
    @Path("/me")
    @Authenticated
    @Operation(
        summary = "Get current user",
        description = "Returns the profile information of the authenticated user based on the provided JWT token."
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "User profile retrieved successfully",
            content = @Content(schema = @Schema(implementation = ApiUser.class))
        ),
        @APIResponse(responseCode = "401", description = "Unauthorized - missing or invalid token"),
        @APIResponse(responseCode = "404", description = "User not found")
    })
    public Uni<ApiUser> getCurrentUser(@Context SecurityContext ctx) {
        return userService.getUser(ctx.getUserPrincipal().getName())
            .onItem().transform(user -> new ApiUser(user.email, user.name, user.picture));
    }
}
