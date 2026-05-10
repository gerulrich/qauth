package quantum.auth.api;

import jakarta.validation.constraints.NotBlank;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(description = "Google Sign-In request payload")
public record GoogleTokenRequest(
    @Schema(description = "Google ID token") @NotBlank String token
) {
}

