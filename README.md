![Status Splunk app](status/static/appIcon_2x.png?)
# Status
This is a Splunk custom REST endpoint to consolidate many status/health checks into one place. This allows devices like load balancers to do a single health check to Splunk and get a cumulative response.

## Details
* Is exposed on Splunk's web port and accessible via:
    * `/splunkd/__raw/services/status/v1/health` on the web port
    * `/services/status/v1/health` on the management port
* Requires no authentication by default for the exposed REST endpoint
    * Can set `requireAuthentication=true` in [restmap.conf](status/default/restmap.conf) to turn it on
        * If `requireAuthentication=true` is used then the endpoint needs to be accessed via the management port.
    * Can set `acceptFrom` in [restmap.conf](status/default/restmap.conf) to limit what IPs can access
* Authentication is required for the REST endpoint to access splunkd API internally.
    * See [Create authentication tokens](https://docs.splunk.com/Documentation/Splunk/latest/Security/CreateAuthTokens) on how to set up a token.
    * The user the token is created for must have the following capabilities
        * `list_search_head_clustering`
        * `search`
        * `list_settings`
    * The token is required in the endpoint configuration file - [status_rest_handler.conf](status/default/status_rest_handler.conf)

## Checks
All checks are on by default with the exception of the *web port* check. Since this endpoint is exposed via the web port, that check is good as long as the endpoint is working. If using the management port, the *web port* check could be turned on.
* kvstore status
* search head cluster status
* HEC port up/down
* web port
* splunkd management port

## Configuration
The configurations are in [status_rest_handler.conf](status/default/status_rest_handler.conf) and documented there.

## Returns
JSON is returned with the following formats.

### Success JSON
```
{
    "message": {
        "hec_status": "ready",
        "kvstore_disabled": "0",
        "kvstore_replication_status": "non-captain kv store member",
        "kvstore_standalone": "0",
        "kvstore_status": "ready",
        "overall_status": 1,
        "shc_is_registered": "1",
        "shc_maintenance_mode": "0",
        "shc_status": "up",
        "shc_captain_service_ready_flag": "1",
        "splunkd_status": "ready",
        "web_status": null
    },
    "success": true
}
```

### Error JSON
```
{
    "success": false,
    "message": "[ERROR] <AuthenticationFailed> [HTTP 401] Client is not authenticated"
}
```

