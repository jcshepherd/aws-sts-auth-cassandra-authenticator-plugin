TODO: Fill this out.

For now ...

Users of this plug-in are STRONGLY recommended to not send requests to the sts.amazonaws.com
endpoint of AWS Security Token Service. That endpoint is located in single AWS region
(us-east-1) and while it maintains high availability, it is subject to region-impacting events
and does not support automated fail-over to STS endpoints in other regions. Please use the
region-specific endpoint "nearest" your Cassandra cluster, as documented here:
https://docs.aws.amazon.com/general/latest/gr/sts.html .
