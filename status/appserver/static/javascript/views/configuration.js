"use strict";

export async function perform(splunk_js_sdk, setup_options) {
    var app_name = "status";

    var application_name_space = {
        owner: "nobody",
        app: app_name,
        sharing: "app",
    };

    try {
        var http = new splunk_js_sdk.SplunkWebHttp();
        const splunk_js_sdk_service = new splunk_js_sdk.Service(
            http,
            application_name_space
        );

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

        /*
        // set app to configured and reload it
        var applications = splunk_js_sdk_service.apps();
        await applications.fetch();
        
        var app = applications.item(app_name);
        await app.fetch();

        await app.post("", {configured: true}, function(err, response){
            if (err != null){
                console.log("ERROR: " + err);
            }
            else if (response.status != 200) {
                console.log(response);
            }
        });

        await app.reload();
        */
    }
    catch (err) {
        console.log('ERROR: ' + err);
    }
}

