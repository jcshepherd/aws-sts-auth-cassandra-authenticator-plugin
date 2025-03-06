# IMPORTANT: EXPERIMENTAL USE ONLY

The code in this package is still in development. **IT IS NOT SUITABLE FOR PRODUCTION USE**
at this time, and will be moved to a different repository when released.

# About

An Apache Cassandra authenticator plugin which enables clients to use their AWS Identity and Access Management (IAM)
credentials to authenticate to a Cassandra node. A matching plugin for the Java driver is available in a separate
repo: https://github.com/jcshepherd/aws-sts-auth-cassandra-java-driver-plugin . The two requirements for using these
plugins are:
1. The client must be able to provide valid AWS IAM credentials that can be used to sign a request with AWS SigV4. If
successfully authenticated, the client's identity will be represented by the ARN of the AWS IAM principal associated
with the signing credentials.
2. The node must be able to reach (i.e. connect over the Internet) the
[AWS Security Token Service](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html) endpoint specified by
the client in its authentication response.

Neither the node nor client need to run on AWS infrastructure, and the node itself does not need to be associated with
any AWS account.

# Using the Plugin

The plugin in its current state builds for Cassandra 5 only. Builds for other Cassandra versions are coming.

## Configuration

To use this authenticator plugin, you need to add it to your Cassandra node's classpath and configure Cassandra to
use the plugin for authentication.

### Classpath

Build and place the jar in Cassandra's `CLASSPATH` (e.g. by placing it in the `libs` directory of the Cassandra
installation, or modifying `conf/cassandra-env.sh` to add the jar path to the `CLASSPATH`).

### Configuration


Add/modify the following configuration in your installation's `conf/cassandra.yaml` file:
```
authenticator:
  class_name: software.aws.cassandra.sts.auth.AWSIdentitySTSAuthenticator
```

You will need to restart your node or cluster for these changes to take effect. Note that currently Cassandra can
support a single authenticator: a node enabled for IAM-based authentication won't be able to authenticate by other
mechanisms.

# Notes

Client-side users of this authenticator are STRONGLY recommended to not to use the "global" sts.amazonaws.com endpoint
of the AWS Security Token Service (STS). That endpoint is located in single AWS region (us-east-1) and while it
maintains high availability, it is subject to region-impacting events and does not support automated fail-over to STS
endpoints in other regions. Please use the region-specific endpoint "nearest" the Cassandra cluster you wish to
connect to, as documented here: https://docs.aws.amazon.com/general/latest/gr/sts.html .
