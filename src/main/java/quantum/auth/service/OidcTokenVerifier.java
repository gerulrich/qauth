package quantum.auth.service;

import jakarta.inject.Qualifier;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/// CDI qualifier selecting the **configured OIDC provider's ID token verifier**.
///
/// Applied to the verifier bean and matching [TokenVerifierService] injection points
/// to distinguish it from the Google verifier.
@Qualifier
@Retention(RUNTIME)
@Target({FIELD, METHOD, PARAMETER, TYPE})
public @interface OidcTokenVerifier {
}
