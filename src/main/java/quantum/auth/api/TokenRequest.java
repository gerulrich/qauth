package quantum.auth.api;

import jakarta.validation.constraints.NotBlank;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/// Credentials used to obtain a **JWT access token** and an opaque refresh token.
///
/// Bean Validation rejects `null`, empty, or blank credentials when the request is validated.
///
/// @param email email address identifying the user account
/// @param password plaintext password to verify against the stored password hash
@Schema(description = "Credentials required to obtain a JWT token")
public record TokenRequest(
    @Schema(description = "User email address") @NotBlank String email,
    @Schema(description = "User password") @NotBlank String password
) {
}
