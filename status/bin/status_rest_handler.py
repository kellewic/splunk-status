import logging, os, re, socket, sys
import splunk
import splunk.entity
import splunk.util
from splunk.conf_util import ConfigMap, ConfigMapError

file_realpath = os.path.realpath(__file__)

script_dir = os.path.dirname(file_realpath)
script_name = os.path.splitext(os.path.basename(file_realpath))[0]

app_name = re.sub(r'^.*?/apps/(.*?)(?:/|$)(?:.*$)?', r'\1', script_dir)

conf_file_name = "{}.conf".format(script_name)
conf_file_default_path = os.path.join(script_dir, "..", "default", conf_file_name)
conf_file_local_path = os.path.join(script_dir, "..", "local", conf_file_name)

logger = logging.getLogger(script_name)

## app-specific libs
sys.path.insert(0, os.path.join(script_dir, "..", "lib"))
import rest_handler
import splunklib.client as client

## Checks the status/health of various Splunk components. This service is exposed via the Splunk web port.
## The following are monitored:
##
## Web port - health check to this endpoint will indicate if the web port is up or down
## Mgmt port - this endpoint uses multiple REST calls to the management port and will fail if it's not functioning
## KV store status - checks via /services/kvstore/status endpoint
## KV store replication status - checks via /services/kvstore/status endpoint
## HEC port - connects to socket to see if it's up
##
## TODO:
## check with authenticationRequired = true
##  - overrides the token inside config files
##
## SHC status - /services/shcluster/member/info
## SSL cert checks
## Check with kvstore disabled so port isn't up
## Check HEC via <protocol>://<host>:8088/services/collector/health using requests module
##
## Configuration page to set value in local conf file.
##
class StatusHandler_v1(rest_handler.RESTHandler):
    def __init__(self, command_line, command_arg):
        super(StatusHandler_v1, self).__init__(command_line, command_arg, logger)

        ## Health check details returned
        self.health_data = {
            "overall_status": -1,
            "kvstore_status": None,
            "kvstore_replication_status": None,
            "hec_status": None,
        }

        ## List of 0/1 indicators that become the overall_status in health_data
        self.status_checks = []

        ## key/value pairs of config options
        self.config = {}

        ## Captures any exceptions when loading configs since they are ignored
        ## when caught within __init__
        self.return_now = None

        self.fd = open("/tmp/tmpAAAAAAA", "w")

        try:
            default_config = ConfigMap(conf_file_default_path)

            ## local config isn't needed if the default config was modified
            try:
                local_config = ConfigMap(conf_file_local_path)
            except:
                local_config = {"default": {}}

            self.config = splunk.util.normalizeBoolean({**(default_config["default"]), **(local_config["default"])})

        except ConfigMapError as e:
            self.return_now = self.render_error_json("Config file at {} does not exist".format(conf_file_default_path))

        except Exception as e:
            self.return_now = self._render_generic_error_json(e)

    ## Send back a generic error message
    def _render_generic_error_json(self, e, message=None):
        if message is None:
            message = str(e)

        return self.render_error_json("[ERROR] <{}> {}".format(str(type(e).__name__), message))

    ## Get config value for entry and cast to "typ" if specified; otherwise it's returned as str
    def get_config_value(self, entry, typ=str):
        return typ(self.config.get(entry, None))

    ## Set health check value
    def set_health_data_entry(self, entry, val):
        if isinstance(val, str):
            self.health_data[entry] = val.lower()
        else:
            self.health_data[entry] = val

    ## Get health check value
    def get_health_data_entry(self, entry):
        return self.health_data[entry]

    ## Add entry to status checks
    def set_status_entry(self, entry, good_vals):
        entry = self.health_data[entry]
        good_vals = [s.lower() for s in good_vals]

        if entry in good_vals:
            self.status_checks.append(1)
        else:
            self.status_checks.append(0)

    ## Sets the overall status based on how many passes/fails exist in status_checks
    def set_overall_status(self):
        if len(self.status_checks) != sum(self.status_checks):
            self.health_data["overall_status"] = 0
        else:
            self.health_data["overall_status"] = 1

    ## Main health check
    def get_health(self, request_info):
        ## Check if __init__ had any exceptions and return them
        if self.return_now is not None:
            return self.return_now

        try:
            entity = None
            session_key = self.get_config_value("token")
            kvstore_status = self.get_config_value("kvstore_status")
            kvstore_replication_status = self.get_config_value("kvstore_replication_status")

            if kvstore_status or kvstore_replication_status:
                try:
                    entity = splunk.entity.getEntity('/kvstore', 'status', namespace=app_name, sessionKey=session_key, owner='-')

                except splunk.ResourceNotFound as e:
                    return self._render_generic_error_json(e, message="There was an issue accessing /services/kvstore/status REST endpoint. The resource could not be found.")

                except Exception as e:
                    return self._render_generic_error_json(e)

            ## KV store status
            if kvstore_status:
                kvstore_status = entity["current"]["status"]
                self.set_health_data_entry("kvstore_status", kvstore_status)
                self.set_status_entry("kvstore_status", ["ready"])

            ## KV store replication status
            if kvstore_replication_status:
                kvstore_replication_status = entity["current"]["replicationStatus"]
                self.set_health_data_entry("kvstore_replication_status", kvstore_replication_status)
                self.set_status_entry("kvstore_replication_status", ["KV Store captain", "Non-captain KV Store member"])

            ## HEC status
            if self.get_config_value("hec_status"):
                hec_port = self.get_config_value("hec_port", int)

                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((self.get_config_value("hec_ip"), hec_port))
                    s.close()
                    self.set_health_data_entry("hec_status", "ready")
                except Exception as e:
                    self.set_health_data_entry("hec_status", "failed - {}".format(str(e)))
                finally:    
                    self.set_status_entry("hec_status", ["ready"])


        except splunk.AuthenticationFailed:
            return self.render_error_json("Authentication token expired or invalid", response_code=401)

        except Exception as e:
            return self._render_generic_error_json(e)

        ## Send back response
        try:
            response_code = 200
            success = True

            self.set_overall_status()

            if self.get_health_data_entry("overall_status") != 1:
                response_code = 503
                success = False

            self.fd.close()

            return self.render_json({
                'message': self.health_data,
                'success': success,
                'iter': 'PAYLOAD_41',
            }, response_code=response_code)

        except Exception as e:
            return self._render_generic_error_json(e)

