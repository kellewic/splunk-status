import logging, os, re, requests, socket, sys
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
import certifi, rest_handler
import splunklib.client as client

## Constants
DEFAULT = "default"
HEC_PORT = "hec_port"
HEC_IP = "hec_ip"
HEC_STATUS = "hec_status"
IN_SHC = "in_shc"
KVSTORE_DISABLED = "kvstore_disabled"
KVSTORE_REPLICATION_STATUS = "kvstore_replication_status"
KVSTORE_STANDALONE = "kvstore_standalone"
KVSTORE_STATUS = "kvstore_status"
OVERALL_STATUS = "overall_status"
READY = "ready"
READY_LIST = [READY]
SPLUNKD_STATUS = "splunkd_status"
TOKEN = "token"
WEB_STATUS = "web_status"
WEB_STATUS_TIMEOUT = "web_status_timeout"

## TODO:
##
## SSL cert checks
## Check with kvstore disabled so port isn't up
## Check HEC via <protocol>://<host>:8088/services/collector/health using requests module
##
class StatusHandler_v1(rest_handler.RESTHandler):
    def __init__(self, command_line, command_arg):
        super(StatusHandler_v1, self).__init__(command_line, command_arg, logger)

        ## Health check details returned
        self.health_data = {
            OVERALL_STATUS: -1,
            WEB_STATUS: None,
            SPLUNKD_STATUS: None,
            KVSTORE_STATUS: None,
            KVSTORE_REPLICATION_STATUS: None,
            KVSTORE_DISABLED: None,
            KVSTORE_STANDALONE: None,
            HEC_STATUS: None,
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
                local_config = {DEFAULT: {}}

            self.config = splunk.util.normalizeBoolean({**(default_config[DEFAULT]), **(local_config[DEFAULT])})

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
            self.health_data[OVERALL_STATUS] = 0
        else:
            self.health_data[OVERALL_STATUS] = 1

    ## Main health check
    def get_health(self, request_info):
        ## Check if __init__ had any exceptions and return them
        if self.return_now is not None:
            return self.return_now

        try:
            entity = None
            session_key = None
            in_shc = self.get_config_value(IN_SHC, bool)
            kvstore_disabled = self.get_config_value(KVSTORE_DISABLED, bool)
            kvstore_standalone = self.get_config_value(KVSTORE_STANDALONE, bool)
            kvstore_status = self.get_config_value(KVSTORE_STATUS, bool)
            kvstore_replication_status = self.get_config_value(KVSTORE_REPLICATION_STATUS, bool)
            web_status = self.get_config_value(WEB_STATUS, bool)

            ## If an auth token comes from an active user session or via Authorization header
            ## use it over what exists in the config files.
            if request_info.session_key is not None:
                session_key = request_info.session_key
            else:
                session_key = self.get_config_value(TOKEN)


            ## Get info from kvstore endpoint
            if kvstore_status or kvstore_replication_status or kvstore_disabled or kvstore_standalone:
                try:
                    entity = splunk.entity.getEntity('/kvstore', 'status', namespace=app_name, sessionKey=session_key, owner='-')

                except splunk.ResourceNotFound as e:
                    return self._render_generic_error_json(e, message="There was an issue accessing /services/kvstore/status REST endpoint. The resource could not be found.")

                except Exception as e:
                    return self._render_generic_error_json(e)

            else:
                ## Check splunkd port using a generic endpoint
                try:
                    entity = splunk.entity.getEntity('/server', 'settings', namespace=app_name, sessionKey=session_key, owner='-')

                except Exception as e:
                    return self._render_generic_error_json(e)

            ## If we get here then the splunkd management port is working
            self.set_health_data_entry(SPLUNKD_STATUS, READY)
            self.set_status_entry(SPLUNKD_STATUS, READY_LIST)

            ## KV store status
            if kvstore_status:
                kvstore_status = entity["current"]["status"]
                self.set_health_data_entry(KVSTORE_STATUS, kvstore_status)
                self.set_status_entry(KVSTORE_STATUS, READY_LIST)

            ## KV store replication status
            if kvstore_replication_status:
                kvstore_replication_status = entity["current"]["replicationStatus"]
                self.set_health_data_entry(KVSTORE_REPLICATION_STATUS, kvstore_replication_status)
                self.set_status_entry(KVSTORE_REPLICATION_STATUS, ["KV Store captain", "Non-captain KV Store member"])

            ## KV store disabled
            if kvstore_disabled:
                kvstore_disabled = entity["current"]["disabled"]
                self.set_health_data_entry(KVSTORE_DISABLED, kvstore_disabled)
                self.set_status_entry(KVSTORE_DISABLED, ["0"])

            ## KV store standalone
            if kvstore_standalone:
                kvstore_standalone = entity["current"]["standalone"]
                self.set_health_data_entry(KVSTORE_STANDALONE, kvstore_standalone)


            ## SHC status
            if in_shc:
                ## TODO

                if kvstore_standalone:
                    self.set_status_entry(KVSTORE_STANDALONE, ["0"])

                try:
                    entity = splunk.entity.getEntity('/shcluster/member', 'info', namespace=app_name, sessionKey=session_key, owner='-')

                except splunk.ResourceNotFound as e:
                    return self._render_generic_error_json(e, message="There was an issue accessing /services/shcluster/member/info REST endpoint. The resource could not be found.")

                except Exception as e:
                    return self._render_generic_error_json(e)
            else:
                ## TODO

                if kvstore_standalone:
                    self.set_status_entry(KVSTORE_STANDALONE, ["1"])


            ## HEC status
            if self.get_config_value(HEC_STATUS, bool):
                hec_port = self.get_config_value(HEC_PORT, int)

                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((self.get_config_value(HEC_IP), hec_port))
                    s.close()
                    self.set_health_data_entry(HEC_STATUS, READY)
                except Exception as e:
                    self.set_health_data_entry(HEC_STATUS, "failed - {}".format(str(e)))
                finally:    
                    self.set_status_entry(HEC_STATUS, READY_LIST)

            ## Web port check
            if web_status is True:
                ## Set web status based on status arg
                def set_web_status(status):
                    self.set_health_data_entry(WEB_STATUS, status)
                    self.set_status_entry(WEB_STATUS, READY_LIST)

                try:
                    timeout = self.get_config_value(WEB_STATUS_TIMEOUT, int)
                    url = "{}".format(splunk.getWebServerInfo())
                    response = requests.get(url, timeout=timeout, verify=certifi.where())

                    ## Check if we got a 200 HTTP status code and set status accordingly
                    if response.status_code == 200:
                        set_web_status(READY)
                    else:
                        set_web_status("failed - web port returned {} status for {}".format(response.status_code, url))

                except Exception as e:
                    return self._render_generic_error_json(e)


        except splunk.AuthenticationFailed:
            return self.render_error_json("Authentication token expired or invalid")

        except Exception as e:
            return self._render_generic_error_json(e)

        ## Send back response
        try:
            response_code = 200
            success = True

            self.set_overall_status()

            if self.get_health_data_entry(OVERALL_STATUS) != 1:
                response_code = 503
                success = False

            self.fd.close()

            return self.render_json({
                'message': self.health_data,
                'success': success,
                'iter': 'PAYLOAD_54',
            }, response_code=response_code)

        except Exception as e:
            return self._render_generic_error_json(e)

