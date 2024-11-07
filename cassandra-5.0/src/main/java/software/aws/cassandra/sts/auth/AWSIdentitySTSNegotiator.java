package software.aws.cassandra.sts.auth;

import com.google.common.primitives.Bytes;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The AWSIdentitySTSNegotiator class handles the SASL negotiation process for AWS Identity authentication.
 * <p>
 * This negotiator expects the client to provide a pre-signed URL to invoke the GetCallerIdentity API on the AWS
 * Secure Token Service (STS). GetCallerIdentity validates the signature and returns the ARN identifying the principal
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

    /** For nonce generation. */
    private static final SecureRandom RND = new SecureRandom();

    private static final int NONCE_LENGTH_BYTES = 16;

    private byte[] nonce = null;

    /** Magic bytes that we expect to the client to prefix its auth challenge response. */
    private static final byte[] STSBYTES = "AWSSTS".getBytes(StandardCharsets.UTF_8);

    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

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
     * @return An encoded nonce to be included in this node's AUTH_CHALLENGE to the client, or an empty byte array
     *         if the client has successfully authenticated.
     * @throws AuthenticationException
     */
    @Override
    public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException {
        if (Bytes.indexOf(clientResponse, STSBYTES) == 0) {
            if (nonce == null) {
                nonce = newNonce(NONCE_LENGTH_BYTES);
            }
            return ("nonce=" + new String(Base64.getEncoder().encode(nonce))).getBytes(StandardCharsets.UTF_8);
        }

        String callerIdentityRequest = decodeClientResponse(clientResponse);
        URL url = validateSTSRequest(callerIdentityRequest);
        String stsResponse = invokeSTSRequest(url);

        // AWS is a little inconsistent regarding case sensitivity. Usernames are considered case-insensitive,
        // but may appear in mixed case in the ARN. Roles names are considered case-sensitive. For now, to
        // conform to Cassandra's convention of lower-casing "bare" user/role names for case-insensitivity, we
        // force the ARN to lowe-case as well.
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
     * Validates the client-provided presigned STS URL. The "action", version, endpoint and SIGV4 parameters are
     * validated to discourage attempts to invoke non-AWS endpoints, incorrect APIs, etc.
     * <p>
     * {@see https://blog.xargs.io/post/2023-07-01-use-presigned-aws-sts-get-caller-identity-for-authentication/}
     * <p>
     * The expected form of a valid signed URL is:
     * {@code https://sts.amazonaws.com/?Action=GetCallerIdentity
     *            &Version=2011-06-15
     *            &X-Amz-Algorithm=AWS4-HMAC-SHA256
     *            &X-Amz-Credential=<YOUR_ACCESS_KEY_ID>/<date>/<region>/sts/aws4_request
     *            &X-Amz-Date=<timestamp>
     *            &X-Amz-Expires=<expiration_in_seconds>
     *            &X-Amz-SignedHeaders=host
     *            &X-Amz-Signature=<calculated_signature>
     * }
     * @param callerIdentityRequest A pre-signed STS GetCallerIdentity URL provided by a client.
     * @return The URL, if valid.
     * @throws AuthenticationException if the client-provided URL is malformed or otherwise invalid.
     */
    private URL validateSTSRequest(String callerIdentityRequest) {
        URL url;

        try {
            url = new URL(callerIdentityRequest);
        } catch (MalformedURLException e) {
            throw new AuthenticationException("Invalid URL format");
        }

        // TODO - Validate the endpoint
        //throw new AuthenticationException("Invalid STS endpoint");

        // Parse query and validate the query parameters.
        Map<String, String> queryParams = parseQueryString(url.getQuery());

        if (!"GetCallerIdentity".equals(queryParams.get("Action"))) {
            throw new AuthenticationException("Invalid action in STS request");
        }

        if (!"2011-06-15".equals(queryParams.get("Version"))) {
            throw new AuthenticationException("Invalid API version");
        }

        String[] requiredParams = {"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-SignedHeaders", "X-Amz-Signature"};

        for (String param : requiredParams) {
            if (!queryParams.containsKey(param)) {
                throw new AuthenticationException("Missing required parameter: " + param);
            }
        }

        // Validate the expiration time
        long expiresIn = Long.parseLong(queryParams.getOrDefault("X-Amz-Expires", "0"));
        if (expiresIn <= 0 || expiresIn > 900) { // 15 minutes max
            throw new AuthenticationException("Invalid expiration time");
        }

        return url;
    }

    /**
     * Extracts and returns the query parameters from the provided URL.
     * @param query An HTTP URL.
     * @return A map of query parameter names and values.
     */
    private Map<String, String> parseQueryString(String query) {
        Map<String, String> queryParams = new HashMap<>();

        if (query != null) {
            for (String param : query.split("&")) {
                String[] pair = param.split("=");
                if (pair.length == 2) {
                    queryParams.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                            URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
                }
            }
        }

        return queryParams;
    }

    /**
     * Invokes the pre-signed STS request and returns the response as string.
     * @param url A validated, pre-signed STS GetCallerIdentity request URL.
     * @return The STS response as a string. This is a small XML document.
     * @throws AuthenticationException if the STS request fails for any reason.
     */
    private String invokeSTSRequest(URL url) throws AuthenticationException {
        try {
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            int responseCode = conn.getResponseCode();

            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String inputLine;
                StringBuilder response = new StringBuilder();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }

                in.close();

                return response.toString();
            } else {
                throw new AuthenticationException("STS request failed with response code: " + responseCode);
            }
        } catch (IOException e) {
            // TODO - Should this be retryable?
            throw new AuthenticationException("Error invoking STS request", e);
        }
    }

    /**
     * Parses the response to the STS GetCallerIdentity request and returns the authenticated IAM principal's ARN.
     */
    private String parseSTSResponse(String stsResponse) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(stsResponse)));

            String arn = doc.getElementsByTagName("Arn").item(0).getTextContent();
            String account = doc.getElementsByTagName("Account").item(0).getTextContent();
            String userId = doc.getElementsByTagName("UserId").item(0).getTextContent();

            // TODO - Any further validation/processing required?
            return arn;
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new AuthenticationException("Error parsing STS XML response", e);
        }
    }
}
