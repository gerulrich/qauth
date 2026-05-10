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

@ApplicationScoped
public class GoogleTokenVerifierServiceImpl implements GoogleTokenVerifierService {

    private static final Logger LOG = Logger.getLogger(GoogleTokenVerifierServiceImpl.class);
    private static final String INVALID_GOOGLE_TOKEN = "Authorization header is invalid or has been expired";

    @ConfigProperty(name = "google.client-id", defaultValue = "")
    String googleClientId;

    private GoogleIdTokenVerifier verifier;

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

    @Override
    public Uni<String> verifyAndExtractEmail(String idToken) {
        return Uni.createFrom().item(() -> verifyBlocking(idToken))
            .runSubscriptionOn(Infrastructure.getDefaultWorkerPool());
    }

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
