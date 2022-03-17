![Status Splunk app](static/appIcon_2x.png?)
# Status
This is a Splunk custom REST endpoint to consolidate many status/health checks into one place. This allows devices like load balancers to do a single health check to Splunk and get a cumulative response.

## Details
* Is exposed on Splunk's web port and accessible via: 
    * `/splunkd/__raw/services/status/v1/health` on the web port
    * `/services/status/v1/health` on the management port
* Requires no authentication by default
    * Can set `requireAuthentication=true` in [restmap.conf](default/restmap.conf) to turn it on
        * If `requireAuthentication=true` is used then the endpoint needs to be accessed via the management port. In this case, the web port will be checked via an HTTP(S) request.
    * Can set `acceptFrom` in [restmap.conf](default/restmap.conf) to limit what IPs can access

## Checks
* web port
* splunkd management
* kvstore status
* kvstore replication status
* HEC port up/down

## Configuration
The configurations are in [status_rest_handler.conf](default/status_rest_handler.conf) and documented there.

## Returns
JSON is returned with the following formats.

### Success JSON
```
{
    "message": {
        "overall_status": 1,
        "kvstore_status": "ready",
        "kvstore_replication_status": "kv store captain",
        "hec_status": "ready"
        "web_status": "ready",
        "splunkd_status": "ready"
    },
    "success": true
}
```

## Error JSON
```
{
    "success": false,
    "message": "[ERROR] <AuthenticationFailed> [HTTP 401] Client is not authenticated"
}
```
