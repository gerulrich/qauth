package quantum.auth.api;

import jakarta.validation.constraints.NotBlank;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(description = "Request body to obtain a new access token using a refresh token")
public record RefreshRequest(
    @Schema(description = "Opaque refresh token") @NotBlank String refreshToken
) {
}

