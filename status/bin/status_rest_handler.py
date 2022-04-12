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
CONF_STANZA_NAME = "status"
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
SHC_IS_REGISTERED = "shc_is_registered"
SHC_MAINTENANCE_MODE = "shc_maintenance_mode"
SHC_STATUS = "shc_status"
SHC_CAPTAIN_SERVICE_READY_FLAG = "shc_captain_service_ready_flag"
SPLUNKD_STATUS = "splunkd_status"
TOKEN = "token"
WEB_STATUS = "web_status"
WEB_STATUS_TIMEOUT = "web_status_timeout"

READY_LIST = [READY]
ZERO_LIST = ["0"]
ONE_LIST = ["1"]


## REST endpoint class
class StatusHandler_v1(rest_handler.RESTHandler):
    def __init__(self, command_line, command_arg):
        super(StatusHandler_v1, self).__init__(command_line, command_arg, logger)

        ## Health check details returned
        self.health_data = {
            HEC_STATUS: None,
            KVSTORE_DISABLED: None,
            KVSTORE_REPLICATION_STATUS: None,
            KVSTORE_STANDALONE: None,
            KVSTORE_STATUS: None,
            OVERALL_STATUS: -1,
            SHC_IS_REGISTERED: None,
            SHC_MAINTENANCE_MODE: None,
            SHC_STATUS: None,
            SHC_CAPTAIN_SERVICE_READY_FLAG: None,
            SPLUNKD_STATUS: None,
            WEB_STATUS: None,
        }

        ## List of 0/1 indicators that become the overall_status in health_data
        self.status_checks = []

        ## key/value pairs of config options
        self.config = {}

        ## Captures any exceptions when loading configs since they are ignored
        ## when caught within __init__
        self.return_now = None

        try:
            default_config = ConfigMap(conf_file_default_path)

            ## local config isn't needed if the default config was modified
            try:
                local_config = ConfigMap(conf_file_local_path)
            except:
                local_config = {CONF_STANZA_NAME: {}}

            self.config = splunk.util.normalizeBoolean({**(default_config[CONF_STANZA_NAME]), **(local_config[CONF_STANZA_NAME])})

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

    ## Save status values for individual and overall status determinations
    def process_status(self, config_val, status_key, status_val, status_good_vals):
        if config_val:
            self.set_health_data_entry(status_key, status_val)
            self.set_status_entry(status_key, status_good_vals)

    ## Sets the overall status based on how many passes/fails exist in status_checks
    def set_overall_status(self):
        if len(self.status_checks) != sum(self.status_checks):
            self.health_data[OVERALL_STATUS] = 0
        else:
            self.health_data[OVERALL_STATUS] = 1

    ## Wrapper around splunk.getEntity() to catch and return common exceptions
    def get_entity(self, entityPath, entityName, namespace=None, sessionKey=None):
        error = None
        entity = None

        try:
            entity = splunk.entity.getEntity(entityPath, entityName, namespace=namespace, sessionKey=sessionKey, owner='-')

        except splunk.ResourceNotFound as e:
            message = "There was an issue accessing /services{}/{} REST endpoint. The resource could not be found.".format(entityPath, entityName)
            error = self._render_generic_error_json(e, message=message)

        except Exception as e:
            error = self._render_generic_error_json(e)

        return (entity, error)


    ## Health check handler
    def get_health(self, request_info):
        ## Check if __init__ had any exceptions and return them
        if self.return_now is not None:
            return self.return_now

        try:
            entity = None
            session_key = None
            in_shc = self.get_config_value(IN_SHC, bool)
            hec_status = self.get_config_value(HEC_STATUS, bool)
            kvstore_disabled = self.get_config_value(KVSTORE_DISABLED, bool)
            kvstore_standalone = self.get_config_value(KVSTORE_STANDALONE, bool)
            kvstore_status = self.get_config_value(KVSTORE_STATUS, bool)
            kvstore_replication_status = self.get_config_value(KVSTORE_REPLICATION_STATUS, bool)
            shc_is_registered = self.get_config_value(SHC_IS_REGISTERED, bool)
            shc_maintenance_mode = self.get_config_value(SHC_MAINTENANCE_MODE, bool)
            shc_status = self.get_config_value(SHC_STATUS, bool)
            shc_captain_service_ready_flag = self.get_config_value(SHC_CAPTAIN_SERVICE_READY_FLAG, bool)
            web_status = self.get_config_value(WEB_STATUS, bool)

            ## If an auth token comes from an active user session or via Authorization header
            ## use it over what exists in the config files.
            if request_info.session_key is not None:
                session_key = request_info.session_key
            else:
                session_key = self.get_config_value(TOKEN)


            ## Call KV store endpoint if configuration requires it
            if kvstore_status or kvstore_replication_status or kvstore_disabled or kvstore_standalone:
                (entity, error) = self.get_entity('/kvstore', 'status', namespace=app_name, sessionKey=session_key)

                if error is not None:
                    return error

            else:
                ## If kvstore status isn't configured, this checks the splunkd port
                (entity, error) = self.get_entity('/server', 'settings', namespace=app_name, sessionKey=session_key)

                if error is not None:
                    return error


            ## If we get here then the splunkd port is working
            self.process_status(True, SPLUNKD_STATUS, READY, READY_LIST)

            ## KV store status
            self.process_status(kvstore_status, KVSTORE_STATUS, entity["current"]["status"], READY_LIST)
            self.process_status(kvstore_replication_status, KVSTORE_REPLICATION_STATUS, entity["current"]["replicationStatus"], ["KV Store captain", "Non-captain KV Store member"])
            self.process_status(kvstore_disabled, KVSTORE_DISABLED, entity["current"]["disabled"], ZERO_LIST)


            ## SHC status
            if in_shc:
                ## "0" is a valid value for SHC kvstore
                self.process_status(kvstore_standalone, KVSTORE_STANDALONE, entity["current"]["standalone"], ZERO_LIST)

                ## SHC member status
                (entity, error) = self.get_entity('/shcluster/member', 'info', namespace=app_name, sessionKey=session_key)

                if error is not None:
                    return error

                self.process_status(shc_is_registered, SHC_IS_REGISTERED, entity["is_registered"], ONE_LIST)
                self.process_status(shc_maintenance_mode, SHC_MAINTENANCE_MODE, entity["maintenance_mode"], ZERO_LIST)
                self.process_status(shc_status, SHC_STATUS, entity["status"], ["Up"])

                ## SHC status
                (entity, error) = self.get_entity('/shcluster', 'status', namespace=app_name, sessionKey=session_key)

                if error is not None:
                    return error

                self.process_status(shc_captain_service_ready_flag, SHC_CAPTAIN_SERVICE_READY_FLAG, entity["captain"]["service_ready_flag"], ONE_LIST)

            else:
                ## "1" is a valid value for non-SHC kvstore
                self.process_status(kvstore_standalone, KVSTORE_STANDALONE, entity["current"]["standalone"], ONE_LIST)


            ## HEC CHECKS
            if hec_status:
                hec_port = self.get_config_value(HEC_PORT, int)

                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((self.get_config_value(HEC_IP), hec_port))
                    s.close()
                    self.process_status(True, HEC_STATUS, READY, READY_LIST)

                except Exception as e:
                    self.process_status(True, HEC_STATUS, "failed - {}".format(str(e)), READY_LIST)


            ## Web port check
            if web_status:
                try:
                    timeout = self.get_config_value(WEB_STATUS_TIMEOUT, int)
                    url = "{}".format(splunk.getWebServerInfo())
                    response = requests.get(url, timeout=timeout, verify=certifi.where())

                    ## Check if we got a 200 HTTP status code and set status accordingly
                    if response.status_code == 200:
                        self.process_status(True, WEB_STATUS, READY, READY_LIST)

                    else:
                        self.process_status(True, WEB_STATUS, "failed - web port returned {} status for {}".format(response.status_code, url), READY_LIST)

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

            return self.render_json({
                'message': self.health_data,
                'success': success,
                'iter': 'PAYLOAD_56',
            }, response_code=response_code)

        except Exception as e:
            return self._render_generic_error_json(e)

