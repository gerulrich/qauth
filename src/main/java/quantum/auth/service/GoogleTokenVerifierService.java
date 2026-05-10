package quantum.auth.service;

import io.smallrye.mutiny.Uni;

public interface GoogleTokenVerifierService {

    Uni<String> verifyAndExtractEmail(String idToken);
}

