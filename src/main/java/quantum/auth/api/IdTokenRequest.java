package quantum.auth.api;

import jakarta.validation.constraints.NotBlank;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/// Sign-in request containing an **ID token** issued by an external identity provider.
///
/// The endpoint selects the provider used to verify the token.
/// Bean Validation rejects `null`, empty, or blank tokens when the request is validated.
///
/// @param token ID token issued by the external identity provider
@Schema(description = "External identity provider sign-in request")
public record IdTokenRequest(
    @Schema(description = "External identity provider ID token") @NotBlank String token
) {
}
