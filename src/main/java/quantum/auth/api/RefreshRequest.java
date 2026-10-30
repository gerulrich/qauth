package quantum.auth.api;

import jakarta.validation.constraints.NotBlank;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/// Request to obtain new tokens using an **opaque refresh token**.
///
/// The JSON property is `refresh_token` under the application's snake_case naming strategy.
/// Bean Validation rejects `null`, empty, or blank tokens when the request is validated.
///
/// @param refreshToken refresh token previously issued by the application
@Schema(description = "Request body to obtain a new access token using a refresh token")
public record RefreshRequest(
    @Schema(description = "Opaque refresh token")
    @NotBlank String refreshToken
) {
}
