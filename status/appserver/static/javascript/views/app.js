import * as Setup from "./configuration.js";

define(["react", "splunkjs/splunk"], function(react, splunk_js_sdk){
    const e = react.createElement;

    class SetupPage extends react.Component {
        constructor(props) {
            super(props);

            this.state = {
                token: ''
            };

            this.handleChange = this.handleChange.bind(this);
            this.handleSubmit = this.handleSubmit.bind(this);
        }

        handleChange(event) {
            this.setState({ ...this.state, [event.target.name]: event.target.value});
        }

        async handleSubmit(event) {
            event.preventDefault();

            await Setup.perform(splunk_js_sdk, this.state);
        }

        render() {
            return e("div", null, [
                e("h1", null, "Authentication Setup"),
                e("p", null, [
                    "Enter the authentication token created via the ",
                    e("a", {href: "/manager/status/authorization/tokens", target: "_blank"}, "Tokens UI"),
                    ". All other settings are configured in the app's configuration file."
                ]),
                e("div", null, [
                    e("form", { onSubmit: this.handleSubmit }, [
                        e("textarea", { name: "token", value: this.state.token, onChange: this.handleChange, autofocus: true, rows: 6 }),
                        e("input", { type: "submit", value: "Submit" })
                    ])
                ])
            ]);
        }
    }

    return e(SetupPage);
});

