package quantum.auth.api;

import jakarta.validation.constraints.NotBlank;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(description = "Credentials required to obtain a JWT token")
public record TokenRequest(
    @Schema(description = "User email address") @NotBlank String email,
    @Schema(description = "User password") @NotBlank String password
) {
}
