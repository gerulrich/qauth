package quantum.auth.api;

import jakarta.validation.constraints.NotBlank;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(description = "OIDC Sign-In request payload")
public record OidcTokenRequest(
    @Schema(description = "OIDC ID token") @NotBlank String token
) {
}

