package software.aws.cassandra.sts.auth;

import com.google.common.collect.ImmutableSet;
import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.DataResource;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.schema.SchemaConstants;

import java.net.InetAddress;
import java.util.Map;
import java.util.Set;

/**
 * Authenticates client connections by retrieving their AWS identity through presigned requests to getCallerIdentity()
 * on the AWS Secure Token Service (STS) service.
 */
public class AWSIdentitySTSAuthenticator implements IAuthenticator {

    /** {@inheritDoc} */
    @Override
    public boolean requireAuthentication() {
        return true;
    }

    /** {@inheritDoc} */
    @Override
    public Set<? extends IResource> protectedResources()
    {
        return ImmutableSet.of(DataResource.table(SchemaConstants.AUTH_KEYSPACE_NAME, AuthKeyspace.ROLES));
    }

    @Override
    public void validateConfiguration() throws ConfigurationException { }

    @Override
    public void setup() { }

    @Override
    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress)
    {
        return new AWSIdentitySTSNegotiator();
    }

    @Override
    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException
    {
        throw new AuthenticationException("AWS Identity authentication is not supported for CassandraLoginModule");
    }

}
