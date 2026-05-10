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

@ApplicationScoped
public class OidcTokenVerifierServiceImpl implements OidcTokenVerifierService {

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

    @Override
    public Uni<String> verifyAndExtractEmail(String idToken) {
        return Uni.createFrom().item(() -> verifyBlocking(idToken))
            .runSubscriptionOn(Infrastructure.getDefaultWorkerPool());
    }

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

    private String normalizeOptional(String value) {
        return UNSET.equals(value) ? "" : value;
    }
}




