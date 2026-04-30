package quantum.auth.api;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(description = "Authenticated user profile information")
public record ApiUser(
    @Schema(description = "User's email address", examples = "user@example.com") String email,
    @Schema(description = "User's display name", examples = "John Doe") String name,
    @Schema(description = "URL of the user's profile picture", examples = "https://example.com/avatar.png") String picture
) {}
