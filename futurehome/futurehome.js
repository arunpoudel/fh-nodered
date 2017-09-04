module.exports = function(RED) {
    var OAuth2= require('oauth').OAuth2;
    var crypto = require("crypto");
    var request = require('request');

    function FuturehomeOAuthNode(config) {
        RED.nodes.createNode(this,config);
    }

    RED.nodes.registerType("futurehome-credentials", FuturehomeOAuthNode, {
        credentials: {
           username: {type:"text"},
           access_token: {type: "password"},
           refresh_token: {type:"password"},
           sites: {type: "array"},
           base_uri: {type: "text"},
           client_id: {type:"password"},
           client_secret: {type: "password"}
       }
    });

    function getOAuth2(base_uri, client_id, client_secret) {
        return new OAuth2(
            client_id,
            client_secret,
            base_uri,
            'oauth/authorize',
            'oauth/access_token'
        );
    }

    RED.httpAdmin.get('/futurehome/authorize', function(req, res, next) {
        if (!req.query.clientid || !req.query.clientsecret || !req.query.id || !req.query.callback) {
            return res.status(400).send("No parameters configured.");
        }
        var nodeid = req.query.id;

        var credentials = RED.nodes.getCredentials(nodeid) || {};
        credentials.client_id = req.query.clientid || credentials.client_id;
        credentials.client_secret = req.query.clientsecret || credentials.client_secret;
        credentials.base_uri = req.query.baseuri || credentials.base_uri;

        if (!credentials.base_uri || !credentials.client_id || !credentials.client_secret) {
            return res.status(400).send("Base URI, Client Id or client secret not defined.");
        }
        var csrfToken = crypto.randomBytes(18).toString('base64').replace(/\//g, '-').replace(/\+/g, '_');
        res.cookie('csrf', csrfToken);
        credentials.csrftoken = csrfToken;
        RED.nodes.addCredentials(nodeid, credentials);

        var oa2 = getOAuth2(credentials.base_uri, credentials.client_id, credentials.client_secret);

        var url = oa2.getAuthorizeUrl({redirect_uri : req.query.callback, response_type: "code", state: nodeid + ":" + csrfToken});
        res.redirect(url);
    });

    RED.httpAdmin.get('/futurehome/authorize/callback', function(req, res, next) {
        if (req.query.error) {
            return res.send("Error!!! Get description later.");
        }
        var state = req.query.state.split(":");
        var nodeid = state[0];

        var credentials = RED.nodes.getCredentials(nodeid);

        if (!credentials || !credentials.base_uri || !credentials.client_id || !credentials.client_secret) {
            return res.status(400).send("No credentials");
        }
        if(state[1]  !== credentials.csrftoken) {
            return res.status(401).send("Token mismatch");
        }

        var client_id = credentials.client_id;
        var client_secret = credentials.client_secret;
        var base_uri = credentials.base_uri;

        var oa2 = getOAuth2(base_uri, client_id, client_secret);

        var arr = req.url.split('?');
        var callback = req.protocol + "://" + req.get('host') + arr[0];

        oa2.getOAuthAccessToken(
                    req.query.code,
                    {redirect_uri: callback, grant_type : 'authorization_code'},
                    function(error, oauth_access_token, oauth_refresh_token, results){
                        if (error) {
                            var resp = {statusCode: error.statusCode, errorData: error.data};
                            res.send(resp);
                        } else {
                            var api_options = {
                                url: credentials.base_uri + "user/get/data",
                                headers: {
                                    'Authorization': 'Bearer ' + oauth_access_token
                                }
                            };

                            var r = request.get(api_options,function(err, httpResponse, body) {
                                if (err) {
                                    res.send({statusCode: err.statusCode, errorData: err.data});
                                } else {
                                    var result = JSON.parse(body);

                                    credentials.username = result.firstname + " " + result.lastname;

                                    credentials.sites = result.sites;
                                    credentials.access_token = oauth_access_token;
                                    credentials.refresh_token = oauth_refresh_token;

                                    RED.nodes.addCredentials(nodeid,credentials);

                                    res.send("Authorized successfully. You can now close this window/tab.");
                                }
                            });
                        }
                     }
        );
    });

    function FuturehomeSiteNode(config) {
        RED.nodes.createNode(this,config);
    }
    RED.nodes.registerType("site", FuturehomeSiteNode);
}
