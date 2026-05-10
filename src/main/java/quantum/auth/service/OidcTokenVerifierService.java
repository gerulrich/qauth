package quantum.auth.service;

import io.smallrye.mutiny.Uni;

public interface OidcTokenVerifierService {

    Uni<String> verifyAndExtractEmail(String idToken);
}

