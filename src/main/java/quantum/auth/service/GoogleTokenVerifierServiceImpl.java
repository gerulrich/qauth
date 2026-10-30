package quantum.auth.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import io.quarkus.security.UnauthorizedException;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;

/// Verifies **Google ID tokens** and extracts a non-blank, verified email address.
///
/// Blocking verification runs on the worker pool. Audience validation is configured
/// only when `google.client-id` is non-blank.
@ApplicationScoped
@GoogleTokenVerifier
public class GoogleTokenVerifierServiceImpl implements TokenVerifierService {

    private static final Logger LOG = Logger.getLogger(GoogleTokenVerifierServiceImpl.class);
    private static final String INVALID_GOOGLE_TOKEN = "Authorization header is invalid or has been expired";

    @ConfigProperty(name = "google.client-id", defaultValue = "")
    String googleClientId;

    private GoogleIdTokenVerifier verifier;

    /// Initializes the Google verifier with an audience restriction when configured.
    @PostConstruct
    void init() {
        GoogleIdTokenVerifier.Builder builder = new GoogleIdTokenVerifier.Builder(
            new NetHttpTransport(),
            GsonFactory.getDefaultInstance()
        );

        if (!googleClientId.isBlank()) {
            builder.setAudience(Collections.singletonList(googleClientId));
        }

        verifier = builder.build();
    }

    /// Verifies a Google ID token on the worker pool.
    ///
    /// @param idToken Google ID token to verify
    /// @return a `Uni` emitting the verified email address, or failing with
    ///         [UnauthorizedException] if verification fails or the email is missing or unverified
    @Override
    public Uni<String> verifyAndExtractEmail(String idToken) {
        return Uni.createFrom().item(() -> verifyBlocking(idToken))
            .runSubscriptionOn(Infrastructure.getDefaultWorkerPool());
    }

    /// Performs blocking token verification and checks the email claims.
    ///
    /// @param idToken Google ID token to verify
    /// @return the non-blank email address from the verified token
    /// @throws UnauthorizedException if verification fails, the email is missing or unverified,
    ///                               or a security or I/O error occurs
    private String verifyBlocking(String idToken) {
        try {
            GoogleIdToken googleIdToken = verifier.verify(idToken);
            if (googleIdToken == null) {
                LOG.warn("Google token verification returned null");
                throw new UnauthorizedException(INVALID_GOOGLE_TOKEN);
            }

            GoogleIdToken.Payload payload = googleIdToken.getPayload();
            String email = payload.getEmail();
            Boolean emailVerified = payload.getEmailVerified();

            if (email == null || email.isBlank() || !Boolean.TRUE.equals(emailVerified)) {
                throw new UnauthorizedException(INVALID_GOOGLE_TOKEN);
            }

            return email;
        } catch (GeneralSecurityException | IOException e) {
            LOG.warnf("Google token verification error: %s", e.getMessage());
            throw new UnauthorizedException(INVALID_GOOGLE_TOKEN);
        }
    }
}
