package quantum.auth.service;

import jakarta.enterprise.context.ApplicationScoped;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;

/// Hashes and verifies passwords using **Argon2id**.
///
/// Hashes use the **PHC string format**, which stores everything needed for verification:
///
/// - Argon2 variant and version
/// - Resource parameters
/// - Salt and derived hash
@ApplicationScoped
public class PasswordService {

    private static final String ARGON2D = "argon2d";
    private static final String ARGON2I = "argon2i";
    private static final String ARGON2ID = "argon2id";
    private static final String ARGON2_VERSION_10 = "v=16";
    private static final String ARGON2_VERSION_13 = "v=19";
    private static final String MEMORY_PARAMETER = "m";
    private static final String ITERATIONS_PARAMETER = "t";
    private static final String PARALLELISM_PARAMETER = "p";
    private static final String PHC_HASH_FORMAT = "$%s$%s$m=%d,t=%d,p=%d$%s$%s";

    /// Argon2 resource parameters encoded in a PHC hash.
    ///
    /// @param memoryKb memory cost in **KiB**
    /// @param iterations number of Argon2 iterations
    /// @param parallelism degree of parallelism (lanes)
    private record ParsedParameters(int memoryKb, int iterations, int parallelism) {
    }

    /// Parsed Argon2 settings and the expected derived hash.
    ///
    /// @param parameters Argon2 settings used to derive the hash
    /// @param hash expected hash as a byte array
    private record ParsedHash(Argon2Parameters parameters, byte[] hash) {
    }

    /// Salt length, in bytes.
    private static final int SALT_LENGTH = 16;

    /// Derived hash length, in bytes.
    private static final int HASH_LENGTH = 32;

    /// Cryptographically secure random number generator for salts.
    private static final SecureRandom RANDOM = new SecureRandom();

    /// Argon2 memory cost, in **KiB** (`password.argon2.memory-kb`).
    @ConfigProperty(name = "password.argon2.memory-kb", defaultValue = "4096")
    int memoryKb = 4096;

    /// Number of Argon2 iterations (`password.argon2.iterations`).
    @ConfigProperty(name = "password.argon2.iterations", defaultValue = "2")
    int iterations = 2;

    /// Argon2 degree of parallelism (`password.argon2.parallelism`).
    @ConfigProperty(name = "password.argon2.parallelism", defaultValue = "1")
    int parallelism = 1;

    /// Hashes a password with **Argon2id** and a newly generated random salt.
    ///
    /// @param rawPassword password to hash
    /// @return an Argon2id hash in **PHC string format**
    /// @throws NullPointerException if `rawPassword` is `null`
    public String hash(String rawPassword) {
        char[] password = Objects.requireNonNull(rawPassword, "rawPassword must not be null").toCharArray();
        try {
            return hashArgon2(password);
        } finally {
            clear(password);
        }
    }

    /// Derives an **Argon2id** hash from password characters using the configured parameters.
    ///
    /// @param password password characters to hash
    /// @return an encoded Argon2id hash in **PHC string format**
    /// @throws NullPointerException if `password` is `null`
    /// @throws IllegalArgumentException if the configured Argon2 parameters are invalid
    private String hashArgon2(char[] password) {
        Objects.requireNonNull(password, "password must not be null");
        validateParameters(memoryKb, iterations, parallelism);

        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);

        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(memoryKb)
                .withParallelism(parallelism)
                .withSalt(salt)
                .build();

        byte[] hash = new byte[HASH_LENGTH];
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);
        generator.generateBytes(password, hash, 0, hash.length);

        Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
        return String.format(Locale.ROOT, PHC_HASH_FORMAT, ARGON2ID, ARGON2_VERSION_13,
                memoryKb, iterations, parallelism,
                encoder.encodeToString(salt), encoder.encodeToString(hash));
    }

    /// Verifies a password against an Argon2 hash in **PHC string format**.
    ///
    /// Supported variants and versions:
    ///
    /// - **Argon2d**, **Argon2i**, and **Argon2id**
    /// - Argon2 versions **1.0** and **1.3**
    ///
    /// Malformed or unsupported encodings return `false`.
    ///
    /// @param hash encoded Argon2 hash
    /// @param rawPassword password to check
    /// @return `true` if the password matches; otherwise, `false`
    public boolean verify(String hash, String rawPassword) {
        if (hash == null || rawPassword == null) {
            return false;
        }

        try {
            ParsedHash parsedHash = parseHash(hash);

            char[] passwordChars = rawPassword.toCharArray();
            try {
                byte[] actualHash = new byte[parsedHash.hash().length];
                Argon2BytesGenerator generator = new Argon2BytesGenerator();
                generator.init(parsedHash.parameters());
                generator.generateBytes(passwordChars, actualHash, 0, actualHash.length);
                return MessageDigest.isEqual(parsedHash.hash(), actualHash);
            } finally {
                clear(passwordChars);
            }
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    /// Parses a PHC-encoded Argon2 hash and builds its parameters.
    ///
    /// @param encodedHash PHC string to parse
    /// @return the Argon2 parameters and expected hash bytes
    /// @throws IllegalArgumentException if the encoding is malformed or unsupported
    private static ParsedHash parseHash(String encodedHash) {
        String[] parts = encodedHash.split("\\$", -1);
        if (parts.length != 6 || !parts[0].isEmpty()) {
            throw new IllegalArgumentException("Invalid Argon2 hash format");
        }

        int type = switch (parts[1]) {
            case ARGON2D -> Argon2Parameters.ARGON2_d;
            case ARGON2I -> Argon2Parameters.ARGON2_i;
            case ARGON2ID -> Argon2Parameters.ARGON2_id;
            default -> throw new IllegalArgumentException("Unsupported Argon2 variant");
        };

        int version = switch (parts[2]) {
            case ARGON2_VERSION_10 -> Argon2Parameters.ARGON2_VERSION_10;
            case ARGON2_VERSION_13 -> Argon2Parameters.ARGON2_VERSION_13;
            default -> throw new IllegalArgumentException("Unsupported Argon2 version");
        };

        ParsedParameters parameters = parseParameters(parts[3]);
        validateParameters(parameters.memoryKb(), parameters.iterations(), parameters.parallelism());

        Base64.Decoder decoder = Base64.getDecoder();
        byte[] salt = decoder.decode(parts[4]);
        byte[] hash = decoder.decode(parts[5]);
        if (salt.length == 0 || hash.length == 0) {
            throw new IllegalArgumentException("Argon2 salt and hash must not be empty");
        }

        Argon2Parameters argon2Parameters = new Argon2Parameters.Builder(type)
                .withVersion(version)
                .withMemoryAsKB(parameters.memoryKb())
                .withIterations(parameters.iterations())
                .withParallelism(parameters.parallelism())
                .withSalt(salt)
                .build();
        return new ParsedHash(argon2Parameters, hash);
    }

    /// Parses the `m`, `t`, and `p` values from a PHC parameter field.
    ///
    /// @param encodedParameters comma-separated Argon2 parameters, such as `m=4096,t=2,p=1`
    /// @return the parsed resource parameters
    /// @throws IllegalArgumentException if a parameter is missing, duplicated, unsupported,
    ///                                  or not a positive integer
    private static ParsedParameters parseParameters(String encodedParameters) {
        int memory = 0;
        int iterations = 0;
        int parallelism = 0;

        for (String encodedParameter : encodedParameters.split(",", -1)) {
            String[] keyValue = encodedParameter.split("=", -1);
            if (keyValue.length != 2 || keyValue[1].isEmpty()) {
                throw new IllegalArgumentException("Invalid Argon2 parameter");
            }

            int value = Integer.parseInt(keyValue[1]);
            if (value <= 0) {
                throw new IllegalArgumentException("Argon2 parameters must be positive");
            }
            switch (keyValue[0]) {
                case MEMORY_PARAMETER -> {
                    if (memory != 0) {
                        throw new IllegalArgumentException("Duplicate Argon2 memory parameter");
                    }
                    memory = value;
                }
                case ITERATIONS_PARAMETER -> {
                    if (iterations != 0) {
                        throw new IllegalArgumentException("Duplicate Argon2 iterations parameter");
                    }
                    iterations = value;
                }
                case PARALLELISM_PARAMETER -> {
                    if (parallelism != 0) {
                        throw new IllegalArgumentException("Duplicate Argon2 parallelism parameter");
                    }
                    parallelism = value;
                }
                default -> throw new IllegalArgumentException("Unsupported Argon2 parameter");
            }
        }

        return new ParsedParameters(memory, iterations, parallelism);
    }

    /// Ensures Argon2 parameters are valid and that memory supports the requested lanes.
    ///
    /// @param memory memory cost in **KiB**
    /// @param iterations number of iterations
    /// @param parallelism degree of parallelism (lanes)
    /// @throws IllegalArgumentException if any value is non-positive or memory is too small
    private static void validateParameters(int memory, int iterations, int parallelism) {
        if (memory <= 0 || iterations <= 0 || parallelism <= 0 || memory < 8L * parallelism) {
            throw new IllegalArgumentException("Invalid Argon2 parameters");
        }
    }

    /// Overwrites a temporary password character array with null characters.
    ///
    /// @param value character array to clear
    private static void clear(char[] value) {
        Arrays.fill(value, '\0');
    }
}
