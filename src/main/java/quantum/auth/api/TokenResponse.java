package quantum.auth.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(description = "JWT token response")
public record TokenResponse(
    @JsonProperty("token_type")
    @Schema(description = "Token type", example = "Bearer") String tokenType,
    @JsonProperty("access_token")
    @Schema(description = "Signed JWT access token") String accessToken,
    @JsonProperty("expires_in")
    @Schema(description = "Token expiration time in seconds", example = "900") long expiresIn,
    @JsonProperty("refresh_token")
    @Schema(description = "Opaque refresh token (UUID)") String refreshToken,
    @JsonProperty("refresh_expires_in")
    @Schema(description = "Refresh token expiration time in seconds", example = "2592000") long refreshExpiresIn
) {
}
