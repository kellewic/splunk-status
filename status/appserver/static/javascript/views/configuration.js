"use strict";

export async function perform(splunk_js_sdk, setup_options) {
	// default app name
	var app_name = "status";

	// in case the app gets renamed, figure it out dynamically
	var matches = window.location.href.match(/^.*?\/app\/(?<app_name>.*?)\/.*$/);

	if (matches){
		if (matches.groups && matches.groups['app_name']){
			app_name = matches.groups['app_name'];
		}
	}

    var application_name_space = {
        owner: "nobody",
        app: app_name,
        sharing: "app",
    };

    try {
        const http = new splunk_js_sdk.SplunkWebHttp();
        const splunk_js_sdk_service = new splunk_js_sdk.Service(
            http,
            application_name_space
        );

        // encrypt the token using custom REST endpoint
        await splunk_js_sdk_service.get("/services/status/v1/encrypt", setup_options, function(err, response){
            if (err != null){
                console.log("ERROR: " + err);
            }

            setup_options.token = response.data.message;
        });

        // check that token is encrypted
        if (setup_options.token.startsWith('$7$')){
            delete setup_options.output_mode;

            var configurations = splunk_js_sdk_service.configurations(application_name_space);
            await configurations.fetch();

            // update configuration file
            var config_file = configurations.item('status_rest_handler');
            await config_file.fetch();

            var stanza = config_file.item('status');
            await stanza.fetch();

            await stanza.update(setup_options, function(err, entity){
                if (err != null){
                    console.log("ERROR: " + err);
                }
            });
        }
        else {
            // token string is likely empty if we get here
            console.log("TOKEN NOT ENCRYPTED");
        }
    }
    catch (err) {
        console.log('ERROR: ' + err);
    }
}

