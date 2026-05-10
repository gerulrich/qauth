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
    GoogleTokenVerifierService googleTokenVerifierService;

    @ConfigProperty(name = "mp.jwt.verify.issuer", defaultValue = "quantumlab")
    String issuer;

    @ConfigProperty(name = "jwt.expires-seconds", defaultValue = "900")
    long defaultExpiresSeconds;

    @ConfigProperty(name = "jwt.refresh-expires-seconds", defaultValue = "2592000")
    long refreshExpiresSeconds;

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

    private TokenResponse buildTokenResponse(User user) {
        return buildTokenResponse(user, null);
    }

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

    private boolean isUserEnabled(User user) {
        return user.enabled;
    }

    private boolean isPasswordValid(User user, String password) {
        if (!passwordService.verify(user.password, password)) {
            LOG.warnf("User %s has no password set or password does not match", user.email);
            return false;
        }
        return true;
    }

    private Uni<User> item(User user) {
        return Uni.createFrom().item(user);
    }

    private int computeLevel(String plan) {
        return switch (plan == null ? "" : plan.toLowerCase()) {
            case "basic" -> 1;
            case "pro" -> 2;
            default -> 3;
        };
    }

    private String maskEmail(String email) {
        int atIndex = email.indexOf("@");
        if (atIndex > 1) {
            return String.format("%c***%s", email.charAt(0), email.substring(atIndex));
        }
        return "***";
    }

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
