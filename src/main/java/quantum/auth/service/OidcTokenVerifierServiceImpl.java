package quantum.auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import io.quarkus.security.UnauthorizedException;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/// Verifies **RS256 OIDC ID tokens** using the configured provider's JWK set.
///
/// The JWK set URI is configured explicitly or resolved through OIDC discovery.
/// Issuer and audience checks apply when their corresponding settings are non-blank.
/// Verification requires an expiration time and a verified, non-blank email address.
@ApplicationScoped
@OidcTokenVerifier
public class OidcTokenVerifierServiceImpl implements TokenVerifierService {

    private static final Logger LOG = Logger.getLogger(OidcTokenVerifierServiceImpl.class);
    private static final String INVALID_OIDC_TOKEN = "Authorization header is invalid or has been expired";
    private static final String UNSET = "__unset__";

    @Inject
    ObjectMapper objectMapper;

    @ConfigProperty(name = "oidc.issuer", defaultValue = UNSET)
    String issuer;

    @ConfigProperty(name = "oidc.client-id", defaultValue = UNSET)
    String clientId;

    @ConfigProperty(name = "oidc.jwks-uri", defaultValue = UNSET)
    String jwksUri;

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
    private boolean verifierConfigured;

    /// Initializes the JWT processor using an explicit or discovered JWK set URI.
    ///
    /// Leaves verification disabled when both the issuer and JWK set URI are unset.
    ///
    /// @throws IllegalStateException if configured verifier initialization fails
    @PostConstruct
    void init() {
        try {
            issuer = normalizeOptional(issuer);
            clientId = normalizeOptional(clientId);
            jwksUri = normalizeOptional(jwksUri);

            if (issuer.isBlank() && jwksUri.isBlank()) {
                verifierConfigured = false;
                return;
            }

            String resolvedJwksUri = jwksUri.isBlank() ? discoverJwksUri() : jwksUri;
            URL jwksUrl = URI.create(resolvedJwksUri).toURL();
            JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new RemoteJWKSet<>(jwksUrl));

            DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            processor.setJWSKeySelector(keySelector);
            jwtProcessor = processor;
            verifierConfigured = true;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize OIDC verifier", e);
        }
    }

    /// Verifies an OIDC ID token on the worker pool.
    ///
    /// @param idToken ID token issued by the configured provider
    /// @return a `Uni` emitting the verified email address, or failing with
    ///         [UnauthorizedException] if the verifier is unconfigured or the token is rejected
    @Override
    public Uni<String> verifyAndExtractEmail(String idToken) {
        return Uni.createFrom().item(() -> verifyBlocking(idToken))
            .runSubscriptionOn(Infrastructure.getDefaultWorkerPool());
    }

    /// Verifies the token signature and claims, then extracts its email address.
    ///
    /// @param idToken OIDC ID token to verify
    /// @return the non-blank email address from the verified token
    /// @throws UnauthorizedException if the verifier is unconfigured, token processing fails,
    ///                               required claims are rejected, or the email is missing
    private String verifyBlocking(String idToken) {
        if (!verifierConfigured) {
            LOG.warn("OIDC verifier is not configured");
            throw new UnauthorizedException(INVALID_OIDC_TOKEN);
        }
        try {
            JWTClaimsSet claims = jwtProcessor.process(idToken, null);
            validateClaims(claims);

            String email = claims.getStringClaim("email");
            if (email == null || email.isBlank()) {
                throw new UnauthorizedException(INVALID_OIDC_TOKEN);
            }
            return email;
        } catch (BadJOSEException | JOSEException | ParseException e) {
            LOG.warnf("OIDC token verification error: %s", e.getMessage());
            throw new UnauthorizedException(INVALID_OIDC_TOKEN);
        }
    }

    /// Validates configured issuer and audience constraints, expiration, and email verification.
    ///
    /// The `email_verified` claim accepts Boolean `true` or a case-insensitive `"true"` string.
    ///
    /// @param claims claims extracted by the JWT processor
    /// @throws UnauthorizedException if a required claim is missing or invalid
    /// @throws ParseException if a claim cannot be read with its expected type
    private void validateClaims(JWTClaimsSet claims) throws ParseException {
        if (!issuer.isBlank() && !issuer.equals(claims.getIssuer())) {
            throw new UnauthorizedException(INVALID_OIDC_TOKEN);
        }

        List<String> audience = claims.getAudience();
        if (!clientId.isBlank() && (audience == null || !audience.contains(clientId))) {
            throw new UnauthorizedException(INVALID_OIDC_TOKEN);
        }

        Date expirationTime = claims.getExpirationTime();
        if (expirationTime == null || expirationTime.toInstant().isBefore(Instant.now())) {
            throw new UnauthorizedException(INVALID_OIDC_TOKEN);
        }

        Object emailVerifiedClaim = claims.getClaim("email_verified");
        boolean emailVerified = Boolean.TRUE.equals(emailVerifiedClaim)
            || "true".equalsIgnoreCase(String.valueOf(emailVerifiedClaim));

        if (!emailVerified) {
            throw new UnauthorizedException(INVALID_OIDC_TOKEN);
        }
    }

    /// Resolves `jwks_uri` from the issuer's **OIDC discovery document**.
    ///
    /// Requires an HTTP `200` response and a non-blank `jwks_uri`. When the metadata
    /// includes a non-blank issuer, it must match the configured issuer with its trailing
    /// slash removed. An interrupted HTTP request restores the thread's interrupt flag.
    ///
    /// @return the JWK set URI advertised by the provider
    /// @throws IllegalStateException if the issuer is unset, metadata is invalid,
    ///                               or discovery fails with an I/O error or interruption
    private String discoverJwksUri() {
        if (issuer.isBlank()) {
            throw new IllegalStateException("oidc.issuer must be configured");
        }
        try {
            String normalizedIssuer = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
            URI discoveryUri = URI.create(normalizedIssuer + "/.well-known/openid-configuration");
            HttpRequest request = HttpRequest.newBuilder(discoveryUri).GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new IllegalStateException("Unable to resolve OIDC metadata");
            }

            JsonNode body = objectMapper.readTree(response.body());
            String metadataIssuer = body.path("issuer").asText("");
            if (!metadataIssuer.isBlank() && !normalizedIssuer.equals(metadataIssuer)) {
                throw new IllegalStateException("OIDC metadata issuer mismatch");
            }

            String discovered = body.path("jwks_uri").asText("");
            if (discovered.isBlank()) {
                throw new IllegalStateException("OIDC metadata missing jwks_uri");
            }
            return discovered;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("Unable to resolve OIDC metadata", e);
        }
    }

    /// Converts the configuration placeholder `__unset__` to an empty string.
    ///
    /// @param value configuration value to normalize
    /// @return an empty string for the placeholder, or the original value otherwise
    private String normalizeOptional(String value) {
        return UNSET.equals(value) ? "" : value;
    }
}


