# IMPORTANT: EXPERIMENTAL USE ONLY

The code in this package is still in development. **IT IS NOT SUITABLE FOR PRODUCTION USE** at this time, is subject
to backwards-incompatible changes, and will be moved to a different repository when released.

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

## Building 

Build the project with:
```mvn clean install```

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

# How it Works

This authenticator follows an approach initially developed by Heptio for authenticating to Kubernetes clusters on AWS:
https://github.com/kubernetes-sigs/aws-iam-authenticator . The client obtains IAM credentials: e.g., reading an AWS
key and secret key from environment variables, using an EC2 instance role, etc. When the client initiates a connection
with a Cassandra node that supports this authentication method, it responds to the node's authentication challenge
with a presigned URL request to invoke the `GetCallerIdentity` API on the AWS STS service, signed with the client's
IAM credentials. When the node receives the client's response, it validates the presigned URL and then GETs it
(invokes the API using the client-signed request). If the client's credentials are valid IAM credentials in the same
AWS partition as the STS endpoint, STS responds with the AWS account id, IAM principal name and IAM principal ARN
associated with the client's signing credentials. The principal ARN is the client identity returned to Cassandra by
the authenticator.

There are several measures in place to mitigate potential risks to this approach. To protect against replay attacks,
every client connection attempt is associated with cryptographically random nonce, which is included in the node's
authentication challenge to the client. The client must include the nonce in the presigned URL it provides in its
authentication response. Additionally, this plugin (which runs on the Cassandra node) performs extensive validation
of the client-provided URL to protect against attacks such as directing the request to a non-AWS endpoint.

# Notes

## Use region-specific AWS STS endpoints

Client-side users of this authenticator are STRONGLY recommended not to use the "global" sts.amazonaws.com endpoint
of the AWS Security Token Service (STS). That endpoint is located in single AWS region (us-east-1) and while it
maintains high availability, it is subject to region-impacting events and does not support automated fail-over to STS
endpoints in other regions. Please use the region-specific endpoint "nearest" the Cassandra cluster you wish to
connect to, as documented here: https://docs.aws.amazon.com/general/latest/gr/sts.html .

## Performance

As implemented, validation of the STS endpoint is inefficient. This will be addressed in future revisions.

## Auth Challenge structure

The structure of the auth challenge sent from the node to the client is likely to change before release. In particular,
the revised challenge will include the length of the nonce in bytes, which will be used on the client side to more
safely extract the nonce.
