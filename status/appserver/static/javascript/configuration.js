"use strict";

// default app name
var app_name = "status";

// in case the app gets renamed, figure it out dynamically
var matches = window.location.href.match(/^.*?\/app\/(?<app_name>.*?)\/.*$/);

if (matches){
    if (matches.groups && matches.groups['app_name']){
        app_name = matches.groups['app_name'];
    }
}

require.config({
    paths: {
        myApp: "../app/" + app_name + "/javascript/views/app",
        react: "../app/" + app_name + "/javascript/vendor/react.production.min",
        ReactDOM: "../app/" + app_name + "/javascript/vendor/react-dom.production.min",
    },
    scriptType: "module",
});

require([
    "react", // this needs to be lowercase because ReactDOM refers to it as lowercase
    "ReactDOM",
    "myApp",
], function(react, ReactDOM, myApp) {
    ReactDOM.render(myApp, document.getElementById('main_container'));
});

