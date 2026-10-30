package quantum.auth.service;

import io.smallrye.mutiny.Uni;

/// Verifies **ID tokens** issued by an external identity provider.
///
/// Implementations validate provider-specific tokens and extract a verified email address.
/// Application account lookup and enabled status checks are handled separately.
public interface TokenVerifierService {

    /// Verifies an ID token and extracts its non-blank, verified email address.
    ///
    /// @param idToken ID token issued by the identity provider
    /// @return a `Uni` emitting the verified email address, or failing with
    ///         [io.quarkus.security.UnauthorizedException] if verification fails
    Uni<String> verifyAndExtractEmail(String idToken);
}
