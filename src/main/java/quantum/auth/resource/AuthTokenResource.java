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
import org.eclipse.microprofile.openapi.annotations.enums.SecuritySchemeType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.annotations.security.SecurityScheme;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import quantum.auth.api.IdTokenRequest;
import quantum.auth.api.RefreshRequest;
import quantum.auth.api.TokenRequest;
import quantum.auth.api.TokenResponse;
import quantum.auth.api.UserResponse;
import quantum.auth.service.AuthTokenService;
import quantum.auth.service.UserService;

/// Provides **token issuance**, refresh token rotation, and authenticated user profiles.
///
/// Token endpoints accept JSON without an existing access token.
/// `GET /auth/me` requires a valid bearer JWT.
@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "Authentication", description = "Token issuance, refresh token rotation, and authenticated user profiles")
@SecurityScheme(securitySchemeName = "bearerAuth", type = SecuritySchemeType.HTTP,
    scheme = "bearer", bearerFormat = "JWT", description = "JWT access token issued by this application")
public class AuthTokenResource {

    @Inject
    AuthTokenService authTokenService;

    @Inject
    UserService userService;

    /// Authenticates an enabled user with an email address and password.
    ///
    /// @param request non-blank user credentials
    /// @return a `Uni` emitting a JWT access token and an opaque refresh token
    @POST
    @Path("/token")
    @PermitAll
    @Consumes(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Generate JWT token",
        description = "Authenticates a user with email and password and returns a signed JWT Bearer token."
    )
    @RequestBody(required = true, description = "User email and password",
        content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(implementation = TokenRequest.class)))
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Token generated successfully",
            content = @Content(schema = @Schema(implementation = TokenResponse.class))
        ),
        @APIResponse(responseCode = "401", description = "Invalid credentials, unknown user, or disabled account"),
        @APIResponse(responseCode = "400", description = "Invalid request body")
    })
    public Uni<TokenResponse> generateToken(@Valid TokenRequest request) {
        return authTokenService.generateToken(request.email(), request.password());
    }

    /// Authenticates an existing, enabled user using a **Google ID token**.
    ///
    /// @param request Google ID token to verify
    /// @return a `Uni` emitting application access and refresh tokens
    @POST
    @Path("/token/google")
    @PermitAll
    @Consumes(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Generate JWT token using Google Sign-In",
        description = "Verifies a Google ID token and issues a JWT access token and an opaque refresh token "
            + "for an existing, enabled user. No application access token is required."
    )
    @RequestBody(required = true, description = "Google ID token",
        content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(implementation = IdTokenRequest.class)))
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Token generated successfully",
            content = @Content(schema = @Schema(implementation = TokenResponse.class))
        ),
        @APIResponse(responseCode = "401", description = "Invalid Google token, unknown user, or disabled account"),
        @APIResponse(responseCode = "400", description = "Invalid request body")
    })
    public Uni<TokenResponse> generateTokenWithGoogle(@Valid IdTokenRequest request) {
        return authTokenService.generateTokenFromGoogle(request.token());
    }

    /// Authenticates an existing, enabled user using the configured **OIDC provider**.
    ///
    /// @param request OIDC ID token to verify
    /// @return a `Uni` emitting application access and refresh tokens
    @POST
    @Path("/token/oidc")
    @PermitAll
    @Consumes(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Generate JWT token using OIDC",
        description = "Verifies an ID token from the configured OIDC provider and issues a JWT access token "
            + "and an opaque refresh token for an existing, enabled user. No application access token is required."
    )
    @RequestBody(required = true, description = "ID token from the configured OIDC provider",
        content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(implementation = IdTokenRequest.class)))
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Token generated successfully",
            content = @Content(schema = @Schema(implementation = TokenResponse.class))
        ),
        @APIResponse(responseCode = "401", description = "Invalid OIDC token, unconfigured provider, unknown user, or disabled account"),
        @APIResponse(responseCode = "400", description = "Invalid request body")
    })
    public Uni<TokenResponse> generateTokenWithOidc(@Valid IdTokenRequest request) {
        return authTokenService.generateTokenFromOidc(request.token());
    }
    
    /// Rotates an **opaque refresh token** and issues new access and refresh tokens.
    ///
    /// The submitted refresh token is revoked as part of rotation.
    ///
    /// @param request refresh token previously issued by the application
    /// @return a `Uni` emitting replacement access and refresh tokens
    @POST
    @Path("/refresh")
    @PermitAll
    @Consumes(MediaType.APPLICATION_JSON)
    @Operation(
        summary = "Refresh JWT token",
        description = "Issues a new access token and refresh token using an opaque refresh token. The old refresh token is revoked (rotation)."
    )
    @RequestBody(required = true, description = "Opaque refresh token in the refresh_token property",
        content = @Content(mediaType = MediaType.APPLICATION_JSON, schema = @Schema(implementation = RefreshRequest.class)))
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Tokens refreshed successfully",
            content = @Content(schema = @Schema(implementation = TokenResponse.class))
        ),
        @APIResponse(responseCode = "400", description = "Invalid request body"),
        @APIResponse(responseCode = "401", description = "Unknown, expired, or revoked refresh token, unknown user, or disabled account")
    })
    public Uni<TokenResponse> refreshToken(@Valid RefreshRequest request) {
        return authTokenService.refreshToken(request.refreshToken());
    }

    /// Retrieves the profile associated with the **authenticated principal**.
    ///
    /// @param ctx request security context containing the authenticated user identity
    /// @return a `Uni` emitting the user's email address, display name, and picture URL
    @GET
    @Path("/me")
    @Authenticated
    @SecurityRequirement(name = "bearerAuth")
    @Operation(
        summary = "Get current user",
        description = "Returns the profile information of the authenticated user based on the provided JWT token."
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "User profile retrieved successfully",
            content = @Content(schema = @Schema(implementation = UserResponse.class))
        ),
        @APIResponse(responseCode = "401", description = "Missing, invalid, or expired bearer JWT")
    })
    public Uni<UserResponse> getCurrentUser(@Context SecurityContext ctx) {
        return userService.getUser(ctx.getUserPrincipal().getName())
            .onItem().transform(user -> new UserResponse(user.email, user.name, user.picture));
    }
}
