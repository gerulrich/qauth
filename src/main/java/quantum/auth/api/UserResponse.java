package quantum.auth.api;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/// Profile information for the **authenticated user**.
///
/// @param email email address identifying the user account
/// @param name user's display name
/// @param picture URL of the user's profile picture
@Schema(description = "Authenticated user profile information")
public record UserResponse(
    @Schema(description = "User's email address", examples = "user@example.com") String email,
    @Schema(description = "User's display name", examples = "John Doe") String name,
    @Schema(description = "URL of the user's profile picture", examples = "https://example.com/avatar.png") String picture
) {}
