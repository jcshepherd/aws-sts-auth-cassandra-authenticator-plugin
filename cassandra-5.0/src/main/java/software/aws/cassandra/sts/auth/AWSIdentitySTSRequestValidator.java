package software.aws.cassandra.sts.auth;

import org.apache.cassandra.exceptions.AuthenticationException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.ServiceMetadata;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Utility for validating client-provided STS GetCallerIdentity requests.
 * <p>
 * There are several resources on the Web for real-world background on the validation performed here.<ul>
 *     <li><a href="https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html">Google Project Zero</a></li>
 *     <li><a href="https://blog.xargs.io/post/2023-07-01-use-presigned-aws-sts-get-caller-identity-for-authentication">xargs.io</a></li>
 * </ul>
 */
public class AWSIdentitySTSRequestValidator {

    /**
     * Leftmost label of an AWS STS endpoint DNS name.
     */
    private static final String STS_ENDPOINT_PREFIX = "sts";

    private static final Set<String> stsEndpointsCache = new HashSet<>();

    private static volatile boolean isCacheLoaded = false;

    /**
     * Static methods only: do not construct.
     */
    private AWSIdentitySTSRequestValidator() { }

    /**
     * Validates the client-provided presigned STS URL. The "action", version, endpoint and SIGV4 parameters are
     * validated to discourage attempts to invoke non-AWS endpoints, incorrect APIs, etc.
     * <p>
     * {@see https://blog.xargs.io/post/2023-07-01-use-presigned-aws-sts-get-caller-identity-for-authentication/}
     * <p>
     * The expected form of a valid signed URL is:
     * {@code https://sts.us-east-2.amazonaws.com/?Action=GetCallerIdentity
     *            &Version=2011-06-15
     *            &X-Amz-Algorithm=AWS4-HMAC-SHA256
     *            &X-Amz-Credential=<YOUR_ACCESS_KEY_ID>/<date>/<region>/sts/aws4_request
     *            &X-Amz-Date=<timestamp>
     *            &X-Amz-Expires=<expiration_in_seconds>
     *            &X-Amz-SignedHeaders=host
     *            &X-Amz-Signature=<calculated_signature>
     *            &X-C8-Nonce=<authn_session_nonce>
     * }
     * @param callerIdentityRequest A pre-signed STS GetCallerIdentity URL provided by a client.
     * @return The URL, if valid.
     * @throws AuthenticationException if the client-provided URL is malformed or otherwise invalid.
     */
    public static URL validate(String callerIdentityRequest, byte[] negotiatorNonce) {
        URL url;

        try {
            url = new URL(callerIdentityRequest);
        } catch (MalformedURLException e) {
            throw new AuthenticationException("Invalid URL format");
        }

        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            throw new AuthenticationException("Invalid protocol in STS request");
        }

        if (!isValidSTSEndpoint(url.getHost())) {
            throw new AuthenticationException("Invalid endpoint in STS request");
        }

        // Parse query and validate the query parameters.
        Map<String, String> queryParams = parseQueryString(url.getQuery());

        if (!"GetCallerIdentity".equals(queryParams.get("Action"))) {
            throw new AuthenticationException("Invalid action in STS request");
        }

        if (!"2011-06-15".equals(queryParams.get("Version"))) {
            throw new AuthenticationException("Invalid API version");
        }

        // Validate the expiration time
        long expiresIn = Long.parseLong(queryParams.getOrDefault("X-Amz-Expires", "0"));

        if (expiresIn <= 0 || expiresIn > 900) { // 15 minutes max
            throw new AuthenticationException("Invalid expiration time");
        }

        // Validate the nonce, which is Base64 encoded in the header.
        String clientNonce = queryParams.getOrDefault("X-C8-Nonce", "");

        if (!Arrays.equals(negotiatorNonce, clientNonce.getBytes())) {
            throw new AuthenticationException("Invalid nonce");
        }

        String[] requiredParams = {"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-SignedHeaders", "X-Amz-Signature", "X-C8-Nonce"};

        for (String param : requiredParams) {
            if (!queryParams.containsKey(param)) {
                throw new AuthenticationException("Missing required parameter: " + param);
            }
        }

        return url;
    }


    /**
     * Extracts and returns the query parameters from the provided URL.
     * @param query An HTTP URL.
     * @return A map of query parameter names and values.
     */
    private static Map<String, String> parseQueryString(String query) {
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
     * Indicates if the given host name is a valid AWS STS endpoint in the AWS partition that this node is
     * operating in.
     *
     * @param host Host name to validate: e.g., sts.us-west-1.amazonaws.com.
     * @return True if the host name is a valid STS endpoint in this node's AWS partition; false otherwise.
     */
    private static boolean isValidSTSEndpoint(final String host) {
        /*

        ServiceMetadata md = ServiceMetadata.of(STS_ENDPOINT_PREFIX);

        List<Region> regions = md.regions();

        // Super-inefficient. We'll want some kind of caching of valid endpoints in the partition.
        for (Region region: regions) {
            System.out.println(region + ": " + host + " -> " + md.endpointFor(region));
            if (host.equalsIgnoreCase(md.endpointFor(region).toString())) {
                return true;
            }
        }

         */

        return getStsEndpointsCache().contains(host.toLowerCase());
    }

    private static synchronized Set<String> getStsEndpointsCache() {
        if (!isCacheLoaded) {

            ServiceMetadata md = ServiceMetadata.of(STS_ENDPOINT_PREFIX);

            List<Region> regions = md.regions();

            // Super-inefficient. We'll want some kind of caching of valid endpoints in the partition.
            for (Region region: regions) {
                //System.out.println(region + ": " + host + " -> " + md.endpointFor(region));
                stsEndpointsCache.add(md.endpointFor(region).toString().toLowerCase());
            }

            isCacheLoaded = true;

        }

        return stsEndpointsCache;

    }
}
