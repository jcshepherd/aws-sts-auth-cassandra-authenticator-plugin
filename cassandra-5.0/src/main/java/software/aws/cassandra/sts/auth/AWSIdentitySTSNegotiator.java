package software.aws.cassandra.sts.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.primitives.Bytes;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.utils.JsonUtils;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;

/**
 * The AWSIdentitySTSNegotiator class handles the SASL negotiation process for AWS Identity authentication.
 * <p>
 * This negotiator expects the client to provide a pre-signed URL to invoke the GetCallerIdentity API on the AWS
 * Secure Token Service (STS). GetCallerIdentity validates the signature and returns an ARN identifying the principal
 * that signed the request. Note that invoking GetCallerIdentity doesn't require any permissions grants (in fact, it
 * isn't possible to deny an IAM principal access to the API!). If the client's signature is invalid, or the client
 * provides an invalid URL, this negotiator will reject their authentication attempt.
 * <p>
 * Every client authentication attempt will be handled by a new instance of this negotiator. To discourage replay
 * attacks, a random nonce is generated for each authentication attempt, which the client is expected to include in
 * its response to the negotiator's auth challenge. The negotiator will reject any response that doesn't include
 * the same nonce that it generated.
 */
class AWSIdentitySTSNegotiator implements IAuthenticator.SaslNegotiator {

    /** Magic bytes that we expect to the client to prefix its auth challenge response. */
    private static final byte[] STSBYTES = "AWSSTS".getBytes(StandardCharsets.UTF_8);

    /** Returned by evaluateResponse() to indicate the client has successfully authenticated. */
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    /** For nonce generation. */
    private static final SecureRandom RND = new SecureRandom();

    private static final int NONCE_LENGTH_BYTES = 16;

    /** Random nonce for this authentication attempt. */
    private byte[] nonce = null;

    private static final String NONCE_KEY = "nonce=";

    /** Indicates if the client has successfully completed authentication handshake. */
    private boolean complete = false;

    /**
     * The authenticated "user" name. In practice, this will be an ARN identifying the IAM principal (e.g., a user,
     * a role, etc.) that signed the GetCallerIdentity request successfully invoked by this negotiator. E.g.:
     * {@code arn:aws:iam::123456789012:user/sally}.
     */
    private String userName;

    /**
     * This is typically invoked twice during the handshake. The first time we expect to receive a small hardcoded
     * token that confirms the client intends to authenticate using STS. We respond with an auth challenge that
     * includes a nonce. The next client response should include the nonce, as well as a presigned GetCallerIdentity
     * URL, signed by the IAM principal that the client wishes to authenticate as.
     *
     * @param clientResponse The non-null (but possibly empty) response sent by the client
     * @return A Base-64 encoded nonce to be included in this node's AUTH_CHALLENGE to the client, or an empty byte
     *         array if the client has successfully authenticated.
     * @throws AuthenticationException If the client has provided an invalid GetCallerIdentity request, or if STS
     *         fails to return an authenticated principal identity.
     */
    @Override
    public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException {
        if (Bytes.indexOf(clientResponse, STSBYTES) == 0) {
            if (nonce == null) {
                byte[] newNonce = newNonce(NONCE_LENGTH_BYTES);
                nonce = Base64.getEncoder().encode(newNonce);
            }
            // TODO - I think this should include the length of the encoded nonce: will make client
            // handling more future-proof and also enable the client to easily detect a truncated
            // nonce.
            return (NONCE_KEY + new String(nonce)).getBytes(StandardCharsets.UTF_8);
        }

        String callerIdentityRequest = decodeClientResponse(clientResponse);
        URL url = AWSIdentitySTSRequestValidator.validate(callerIdentityRequest, nonce);
        String stsResponse = invokeSTSRequest(url);

        // AWS is a little inconsistent regarding case sensitivity. Usernames are considered case-insensitive,
        // but may appear in mixed case in the ARN. Roles names are considered case-sensitive. For now, to
        // conform to Cassandra's convention of lower-casing "bare" user/role names for case-insensitivity, we
        // force the ARN to lower-case as well.
        // TODO - This may be the incorrect approach, particularly for IAM role principals.
        userName = parseSTSResponse(stsResponse).toLowerCase(Locale.ROOT);
        complete = true;
        return EMPTY_BYTE_ARRAY;
    }

    /** {@inheritDoc} */
    @Override
    public boolean isComplete() {
        return complete;
    }

    /**
     * {@inheritDoc}
     * <p>
     * This negotiator returns the ARN of the IAM principal that signed the GetCallerIdentity request as the
     * authenticated "user" name.
     */
    @Override
    public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException {
        if (!complete) {
            throw new AuthenticationException("SASL negotiation not complete");
        }

        // TODO - Any further validation before we return the user? What about metadata?
        return new AuthenticatedUser(userName);
    }

    /**
     * Creates and returns a fixed-length nonce of random bytes.
     * @param length Length of the nonce, in bytes.
     * @return A randomly generated nonce.
     */
    private static byte[] newNonce(int length) {
        byte[] randomBytes = new byte[length];
        RND.nextBytes(randomBytes);
        return randomBytes;
    }

    /**
     * Converts the byte array provided in the client's AUTH_RESPONSE message to a simple UTF-8 string.
     * @param clientResponse Byte array from the client response to this node's AUTH_CHALLENGE message.
     * @return The client response as a UTF-8 string.
     */
    private String decodeClientResponse(byte[] clientResponse) {
        if (clientResponse == null || clientResponse.length == 0) {
            throw new AuthenticationException("Required client response is empty");
        }

        return new String(clientResponse, StandardCharsets.UTF_8);
    }

    /**
     * Invokes the pre-signed STS request and returns the response as string.
     * @param url A validated, pre-signed STS GetCallerIdentity request URL.
     * @return The STS response as a string. This is a small XML document.
     * @throws AuthenticationException if the STS request fails for any reason.
     */
    private String invokeSTSRequest(URL url) throws AuthenticationException {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");

            int responseCode = conn.getResponseCode();

            if (responseCode == HttpURLConnection.HTTP_OK) {
                try (InputStream is = conn.getInputStream()) {
                    return IOUtils.toString(is, StandardCharsets.UTF_8);
                }
            } else {
                throw new AuthenticationException("STS request failed with response code: " + responseCode);
            }
        } catch (IOException e) {
            // TODO - Should this be retryable?
            throw new AuthenticationException("Error invoking STS request", e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * Parses the response to the STS GetCallerIdentity request and returns the authenticated IAM principal's ARN.
     */
    private String parseSTSResponse(String stsResponse) {
        JsonNode root = null;

        try {
            root = JsonUtils.JSON_OBJECT_MAPPER.readTree(stsResponse);
        } catch (JsonProcessingException e) {
            throw new AuthenticationException("Invalid response from STS");
        }

        return root.get("GetCallerIdentityResponse")
                   .get("GetCallerIdentityResult")
                   .get("Arn")
                   .asText();
    }
}
