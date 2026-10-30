package quantum.auth.api;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/// Authentication response containing a signed **JWT access token** and an opaque refresh token.
///
/// Expiration values are lifetimes in seconds, not absolute timestamps.
/// JSON property names use the application's snake_case naming strategy,
/// for example `access_token` and `refresh_expires_in`.
///
/// @param tokenType token scheme, such as `Bearer`
/// @param accessToken signed JWT used to access protected resources
/// @param expiresIn access token lifetime in seconds
/// @param refreshToken opaque token used to obtain new tokens
/// @param refreshExpiresIn refresh token lifetime in seconds
@Schema(description = "JWT token response")
public record TokenResponse(
    @Schema(description = "Token type", examples = "Bearer") String tokenType,
    @Schema(description = "Signed JWT access token") String accessToken,
    @Schema(description = "Token expiration time in seconds", examples = "900") long expiresIn,
    @Schema(description = "Opaque refresh token (UUID)") String refreshToken,
    @Schema(description = "Refresh token expiration time in seconds", examples = "2592000") long refreshExpiresIn
) {
}
