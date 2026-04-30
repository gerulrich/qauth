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
import quantum.auth.model.User;
import quantum.auth.repository.UserRepository;

import java.util.HashSet;
import java.util.List;

@ApplicationScoped
public class AuthTokenService {

    private static final Logger LOG = Logger.getLogger(AuthTokenService.class);

    @Inject
    UserRepository userRepository;

    @Inject
    PasswordService passwordService;

    @ConfigProperty(name = "mp.jwt.verify.issuer", defaultValue = "quantumlab")
    String issuer;

    @ConfigProperty(name = "jwt.expires-seconds", defaultValue = "86400")
    long defaultExpiresSeconds;

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
            .onItem().transform(this::buildTokenResponse);
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

    private TokenResponse buildTokenResponse(User user) {
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
        return new TokenResponse("Bearer", token, defaultExpiresSeconds);
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
            return STR."\{email.charAt(0)}***\{email.substring(atIndex)}";
        }
        return "***";
    }
}
