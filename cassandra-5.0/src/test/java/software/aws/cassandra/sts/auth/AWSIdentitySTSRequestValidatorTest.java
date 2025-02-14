package software.aws.cassandra.sts.auth;

import org.apache.cassandra.exceptions.AuthenticationException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link AWSIdentitySTSRequestValidator}.
 */
public class AWSIdentitySTSRequestValidatorTest {

    private static final byte[] SESSION_NONCE = Base64.getEncoder().encode("012345678DEADBEEF".getBytes(StandardCharsets.UTF_8));

    private static String urlEncodedNonce = null;

    @BeforeAll
    public static void beforeAll() {
        urlEncodedNonce = URLEncoder.encode(new String(SESSION_NONCE, StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }

    @Test
    public void testValidSTSRequest() {
        assertDoesNotThrow(() -> AWSIdentitySTSRequestValidator.validate(STSURLBuilder.builder().buildWithDefaults(), SESSION_NONCE));
    }

    @Test
    void testNonHttpsProtocolThrowsException() {
        String request = STSURLBuilder.builder()
                .withProtocol("http")
                .buildWithDefaults();

        AuthenticationException exception = assertThrows(AuthenticationException.class,
                () -> AWSIdentitySTSRequestValidator.validate(request, SESSION_NONCE));

        assertEquals("Invalid protocol in STS request", exception.getMessage());
    }

    @Test
    void testInvalidEndpointThrowsException() {
        String request = STSURLBuilder.builder()
                .withEndpoint("invalid.amazonaws.com")
                .buildWithDefaults();

        AuthenticationException exception = assertThrows(AuthenticationException.class,
                () -> AWSIdentitySTSRequestValidator.validate(request, SESSION_NONCE));

        assertEquals("Invalid endpoint in STS request", exception.getMessage());
    }

    @Test
    void testInvalidActionThrowsException() {
        String request = STSURLBuilder.builder()
                .withAction("GetSessionToken")
                .buildWithDefaults();

        AuthenticationException exception = assertThrows(AuthenticationException.class,
                () -> AWSIdentitySTSRequestValidator.validate(request, SESSION_NONCE));

        assertEquals("Invalid action in STS request", exception.getMessage());
    }

    @Test
    void testInvalidVersionThrowsException() {
        String request = STSURLBuilder.builder()
                .withVersion("2020-01-01")
                .buildWithDefaults();

        AuthenticationException exception = assertThrows(AuthenticationException.class,
                () -> AWSIdentitySTSRequestValidator.validate(request, SESSION_NONCE));

        assertEquals("Invalid API version", exception.getMessage());
    }

    @Test
    void testInvalidNonceThrowsException() {
        String request = STSURLBuilder.builder()
                .withNonce("invalidNonce")
                .buildWithDefaults();

        AuthenticationException exception = assertThrows(AuthenticationException.class,
                () -> AWSIdentitySTSRequestValidator.validate(request, SESSION_NONCE));

        assertEquals("Invalid nonce", exception.getMessage());
    }

    @Test
    void testMissingRequiredParametersThrowsException() {
        String request = STSURLBuilder.builder()
                .withProtocol("https")
                .withEndpoint("sts.eu-west-1.amazonaws.com")
                .withAction("GetCallerIdentity")
                .withVersion("2011-06-15")
                .withExpirationTime(900)
                .withNonce(urlEncodedNonce)
                .buildAsSpecified();

        System.out.println(request);
        AuthenticationException exception = assertThrows(AuthenticationException.class,
                () -> AWSIdentitySTSRequestValidator.validate(request, SESSION_NONCE));

        assertTrue(exception.getMessage().startsWith("Missing required parameter:"));
    }

    @Test
    void testMissingExpirationThrowsException() {
        String request = STSURLBuilder.builder()
                .withExpirationTime(15 * 60 + 1)
                .buildWithDefaults();

        AuthenticationException exception = assertThrows(AuthenticationException.class,
                () -> AWSIdentitySTSRequestValidator.validate(request, SESSION_NONCE));

        assertEquals("Invalid expiration time", exception.getMessage());
    }

    @Test
    void testExpirationTooLongThrowsException() {
        String request = STSURLBuilder.builder()
                .withExpirationTime(15 * 60 + 1)
                .buildWithDefaults();

        AuthenticationException exception = assertThrows(AuthenticationException.class,
                () -> AWSIdentitySTSRequestValidator.validate(request, SESSION_NONCE));

        assertEquals("Invalid expiration time", exception.getMessage());
    }

    @Test
    void testNegativeExpirationThrowsException() {
        String request = STSURLBuilder.builder()
                .withExpirationTime(-1)
                .buildWithDefaults();

        AuthenticationException exception = assertThrows(AuthenticationException.class,
                () -> AWSIdentitySTSRequestValidator.validate(request, SESSION_NONCE));

        assertEquals("Invalid expiration time", exception.getMessage());
    }

    @Test
    void testMalformedURLThrowsException() {
        String malformedUrl = "not-a-url";

        AuthenticationException exception = assertThrows(AuthenticationException.class,
                () -> AWSIdentitySTSRequestValidator.validate(malformedUrl, SESSION_NONCE));
        assertEquals("Invalid URL format", exception.getMessage());
    }

    /**
     * Utility for building URL strings to pass to the validator.
     */
    private static class STSURLBuilder {

        private String protocol;
        private String endpoint;
        private String action;
        private String version;
        private Long expirationInSeconds;
        private String nonce;

        public static STSURLBuilder builder() {
            return new STSURLBuilder();
        }

        public STSURLBuilder withProtocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        public STSURLBuilder withEndpoint(String endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public STSURLBuilder withAction(String action) {
            this.action = action;
            return this;
        }

        public STSURLBuilder withVersion(String version) {
            this.version = version;
            return this;
        }

        public STSURLBuilder withExpirationTime(long expirationInSeconds) {
            this.expirationInSeconds = expirationInSeconds;
            return this;
        }

        public STSURLBuilder withNonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public String buildWithDefaults() {
            protocol = Objects.requireNonNullElse(protocol, "https");
            endpoint = Objects.requireNonNullElse(endpoint, "sts.us-west-2.amazonaws.com");
            action = Objects.requireNonNullElse(action, "GetCallerIdentity");
            version = Objects.requireNonNullElse(version, "2011-06-15");
            expirationInSeconds = Objects.requireNonNullElse(expirationInSeconds, 900L);
            nonce = Objects.requireNonNullElse(nonce, urlEncodedNonce);

            return build(protocol, endpoint, action, version, expirationInSeconds, nonce,
                         "&X-Amz-Algorithm=AWS4-HMAC-SHA256",
                         "&X-Amz-Credential=AKIAXXXXXXXXXXXXXXXX/20230815/us-east-1/sts/aws4_request",
                         "&X-Amz-Date=20230815T123456Z",
                         "&X-Amz-SignedHeaders=host",
                         "&X-Amz-Signature=abcdef1234567890");
        }

        public String buildAsSpecified() {
            return build(protocol, endpoint, action, version, expirationInSeconds, nonce);
        }


        private static String build(String protocol,
                                    String endpoint,
                                    String action,
                                    String version,
                                    Long expirationInSeconds,
                                    String nonce) {
            return build(protocol, endpoint, action, version, expirationInSeconds, nonce,
                         "", "", "", "", "");
        }

        private static String build(String protocol,
                                    String endpoint,
                                    String action,
                                    String version,
                                    Long expirationInSeconds,
                                    String nonce,
                                    String amzAlgorithm,
                                    String amzCredential,
                                    String amzDate,
                                    String amzSignedHeaders,
                                    String amzSignature) {

            StringBuilder sb = new StringBuilder();

            sb.append(protocol).append("://")
              .append(endpoint).append("/?")
              .append("Action=").append(trimToEmpty(action))
              .append("&Version=").append(trimToEmpty(version))
              .append(trimToEmpty(amzAlgorithm))
              .append(trimToEmpty(amzCredential))
              .append(trimToEmpty(amzDate))
              .append("&X-Amz-Expires=").append(expirationInSeconds == null ? 0L : expirationInSeconds)
              .append(trimToEmpty(amzSignedHeaders))
              .append(trimToEmpty(amzSignature))
              .append("&X-C8-Nonce=").append(trimToEmpty(nonce));

            return sb.toString();

        }

        private static String trimToEmpty(String str) {
            return isBlank(str) ? "" : str.trim();
        }

        private static boolean isBlank(String str) {
            return str == null || str.trim().isEmpty();
        }
    }
}
