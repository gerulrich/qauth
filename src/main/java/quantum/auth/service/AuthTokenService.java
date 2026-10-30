package quantum.auth.service;

import io.quarkus.security.UnauthorizedException;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import quantum.auth.api.TokenResponse;
import quantum.auth.model.RefreshToken;
import quantum.auth.model.User;
import quantum.auth.repository.RefreshTokenRepository;
import quantum.auth.repository.UserRepository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

/// Authenticates users and issues **JWT access tokens** and opaque refresh tokens.
///
/// Supports password, Google, and OIDC authentication for existing, enabled accounts.
/// Refresh tokens are stored as hashes and revoked during token rotation.
@ApplicationScoped
public class AuthTokenService {

    private static final Logger LOG = Logger.getLogger(AuthTokenService.class);

    @Inject
    UserRepository userRepository;

    @Inject
    RefreshTokenRepository refreshTokenRepository;

    @Inject
    PasswordService passwordService;

    @Inject
    @GoogleTokenVerifier
    TokenVerifierService googleTokenVerifierService;

    @Inject
    @OidcTokenVerifier
    TokenVerifierService oidcTokenVerifierService;

    @ConfigProperty(name = "mp.jwt.verify.issuer", defaultValue = "quantumlab")
    String issuer;

    @ConfigProperty(name = "jwt.expires-seconds", defaultValue = "900")
    long defaultExpiresSeconds;

    @ConfigProperty(name = "jwt.refresh-expires-seconds", defaultValue = "2592000")
    long refreshExpiresSeconds;

    /// Authenticates an enabled account using its email address and password.
    ///
    /// Password verification runs on the worker pool rather than the calling thread.
    ///
    /// @param email email address identifying the account
    /// @param password plaintext password to verify
    /// @return a `Uni` emitting access and refresh tokens, or failing with
    ///         [UnauthorizedException] if credentials are invalid or the account is disabled
    public Uni<TokenResponse> generateToken(String email, String password) {
        String masked = email != null ? maskEmail(email) : "null";
        LOG.infof("Token generation request received for email: %s", masked);
        return userRepository.findByEmail(email)
            .onItem().ifNull().failWith(() -> {
                LOG.warnf("Login rejected — user not found: %s", masked);
                return new UnauthorizedException("Invalid email or password");
            })
            .onItem().transformToUni(user -> {
                if (!isUserEnabled(user)) {
                    LOG.warnf("Login rejected — account disabled: %s", masked);
                    return Uni.createFrom().failure(new UnauthorizedException("Invalid email or password"));
                }
                return item(user);
            })
            .onItem().transformToUni(user ->
                Uni.createFrom().item(() -> {
                    if (!isPasswordValid(user, password)) {
                        LOG.warnf("Login rejected — invalid password: %s", masked);
                        throw new UnauthorizedException("Invalid email or password");
                    }
                    return user;
                }).runSubscriptionOn(Infrastructure.getDefaultWorkerPool())
            )
            .onItem().transformToUni(this::buildTokenResponseWithRefresh);
    }

    /// Rotates an **opaque refresh token** and issues replacement tokens.
    ///
    /// The stored token is revoked before the associated account is checked and new tokens
    /// are issued. Rotation does not restore the old token if a later operation fails.
    ///
    /// @param rawRefreshToken raw token previously returned to the client
    /// @return a `Uni` emitting replacement tokens, or failing with [UnauthorizedException]
    ///         if the token is unknown, revoked, or expired, or the account is missing or disabled
    public Uni<TokenResponse> refreshToken(String rawRefreshToken) {
        String tokenHash = hash(rawRefreshToken);
        return refreshTokenRepository.findByTokenHash(tokenHash)
            .onItem().ifNull().failWith(() -> {
                LOG.warnf("Refresh rejected — token not found");
                return new UnauthorizedException("Invalid refresh token");
            })
            .onItem().transformToUni(stored -> {
                if (stored.revoked) {
                    LOG.warnf("Refresh rejected — token revoked for: %s", stored.email);
                    return Uni.createFrom().failure(new UnauthorizedException("Invalid refresh token"));
                }
                if (Instant.now().isAfter(stored.expiresAt)) {
                    LOG.warnf("Refresh rejected — token expired for: %s", stored.email);
                    return Uni.createFrom().failure(new UnauthorizedException("Refresh token expired"));
                }
                stored.revoked = true;
                return refreshTokenRepository.persistOrUpdate(stored)
                    .onItem().transformToUni(ignored -> userRepository.findByEmail(stored.email));
            })
            .onItem().ifNull().failWith(() -> new UnauthorizedException("Invalid refresh token"))
            .onItem().transformToUni(user -> {
                if (!isUserEnabled(user)) {
                    LOG.warnf("Refresh rejected — account disabled: %s", maskEmail(user.email));
                    return Uni.createFrom().failure(new UnauthorizedException("Invalid refresh token"));
                }
                return buildTokenResponseWithRefresh(user);
            });
    }

    /// Authenticates an existing, enabled account using a **Google ID token**.
    ///
    /// @param googleToken ID token to verify with Google
    /// @return a `Uni` emitting application tokens, or failing with [UnauthorizedException]
    ///         if token verification fails or the account is missing or disabled
    public Uni<TokenResponse> generateTokenFromGoogle(String googleToken) {
        return googleTokenVerifierService.verifyAndExtractEmail(googleToken)
            .onItem().transformToUni(email -> {
                String masked = maskEmail(email);
                LOG.infof("Google sign-in request received for email: %s", masked);
                return userRepository.findByEmail(email)
                    .onItem().ifNull().failWith(() -> {
                        LOG.warnf("Google sign-in rejected — user not found: %s", masked);
                        return new UnauthorizedException("User is blocked");
                    })
                    .onItem().transformToUni(user -> {
                        if (!isUserEnabled(user)) {
                            LOG.warnf("Google sign-in rejected — account disabled: %s", masked);
                            return Uni.createFrom().failure(new UnauthorizedException("User is blocked"));
                        }
                        return item(user);
                    })
                    .onItem().transformToUni(this::buildTokenResponseWithRefresh);
            });
    }

    /// Authenticates an existing, enabled account using the configured **OIDC provider**.
    ///
    /// @param oidcToken ID token to verify with the configured provider
    /// @return a `Uni` emitting application tokens, or failing with [UnauthorizedException]
    ///         if token verification fails or the account is missing or disabled
    public Uni<TokenResponse> generateTokenFromOidc(String oidcToken) {
        return oidcTokenVerifierService.verifyAndExtractEmail(oidcToken)
            .onItem().transformToUni(email -> {
                String masked = maskEmail(email);
                LOG.infof("OIDC sign-in request received for email: %s", masked);
                return userRepository.findByEmail(email)
                    .onItem().ifNull().failWith(() -> {
                        LOG.warnf("OIDC sign-in rejected — user not found: %s", masked);
                        return new UnauthorizedException("User is blocked");
                    })
                    .onItem().transformToUni(user -> {
                        if (!isUserEnabled(user)) {
                            LOG.warnf("OIDC sign-in rejected — account disabled: %s", masked);
                            return Uni.createFrom().failure(new UnauthorizedException("User is blocked"));
                        }
                        return item(user);
                    })
                    .onItem().transformToUni(this::buildTokenResponseWithRefresh);
            });
    }


    /// Creates an opaque refresh token and persists its hash and expiration metadata.
    ///
    /// @param user account for which tokens are issued
    /// @return a `Uni` emitting the token response after refresh token persistence succeeds
    private Uni<TokenResponse> buildTokenResponseWithRefresh(User user) {
        String rawToken = UUID.randomUUID().toString();
        RefreshToken rt = new RefreshToken();
        rt.tokenHash = hash(rawToken);
        rt.email = user.email;
        rt.expiresAt = Instant.now().plusSeconds(refreshExpiresSeconds);
        rt.revoked = false;
        rt.createdAt = Instant.now();
        return refreshTokenRepository.persist(rt)
            .replaceWith(buildTokenResponse(user, rawToken));
    }


    /// Signs an access JWT and combines it with the supplied refresh token.
    ///
    /// Includes user identity, roles, and plan level claims. Accounts without roles receive
    /// the `user` role; accounts without a MongoDB identifier use their email as `uid`.
    ///
    /// @param user account whose identity and authorization data populate the JWT
    /// @param rawRefreshToken raw refresh token to include in the response
    /// @return the signed access token, refresh token, and their lifetimes
    private TokenResponse buildTokenResponse(User user, String rawRefreshToken) {
        int level = computeLevel(user.plan);
        String uid = user.id != null ? user.id.toHexString() : user.email;
        List<String> roles = user.roles != null && !user.roles.isEmpty() ? user.roles : List.of("user");
        String token = Jwt.issuer(issuer)
                .subject(user.email)
                .groups(new HashSet<>(roles))
                .claim("uid", uid)
                .claim("email", user.email)
                .claim("roles", roles)
                .claim("level", level)
                .expiresIn(defaultExpiresSeconds)
                .sign();
        return new TokenResponse("Bearer", token, defaultExpiresSeconds, rawRefreshToken, refreshExpiresSeconds);
    }

    /// Checks whether an account is enabled for authentication.
    ///
    /// @param user account to check
    /// @return `true` if the account is enabled
    private boolean isUserEnabled(User user) {
        return user.enabled;
    }

    /// Verifies a password against the account's stored hash and logs rejected attempts.
    ///
    /// @param user account containing the stored password hash
    /// @param password plaintext password to verify
    /// @return `true` if the password matches; otherwise, `false`
    private boolean isPasswordValid(User user, String password) {
        if (!passwordService.verify(user.password, password)) {
            LOG.warnf("User %s has no password set or password does not match", user.email);
            return false;
        }
        return true;
    }

    /// Wraps an account in a reactive item.
    ///
    /// @param user account to emit
    /// @return a `Uni` emitting the supplied account
    private Uni<User> item(User user) {
        return Uni.createFrom().item(user);
    }

    /// Maps a plan to the numeric `level` claim included in access tokens.
    ///
    /// @param plan account plan, which may be `null`
    /// @return `1` for `basic`, `2` for `pro`, or `3` for any other value, including `null`
    private int computeLevel(String plan) {
        return switch (plan == null ? "" : plan.toLowerCase()) {
            case "basic" -> 1;
            case "pro" -> 2;
            default -> 3;
        };
    }

    /// Masks an email address for logging, retaining its first character and domain when possible.
    ///
    /// @param email non-null email address to mask
    /// @return the masked address, or `***` if its local part has fewer than two characters
    private String maskEmail(String email) {
        int atIndex = email.indexOf("@");
        if (atIndex > 1) {
            return String.format("%c***%s", email.charAt(0), email.substring(atIndex));
        }
        return "***";
    }

    /// Computes a **SHA-256** hash for opaque refresh token storage and lookup.
    ///
    /// @param value non-null raw token to hash using UTF-8
    /// @return the digest encoded as lowercase hexadecimal
    /// @throws IllegalStateException if SHA-256 is unavailable
    private String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
