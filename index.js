"use strict";
// TODO: Upgrade node version and all packages(dotenv speciallly)
const fs = require('fs')
const express = require('express');
const randomstring = require('randomstring');
const jwt = require('jsonwebtoken');
// const bodyParser = require('body-parser')

require('dotenv').config() //Load environment variables

// Common configs
const PORT = process.env.PORT;
const BASE_URL = process.env.BASE_URL + ":" + PORT

// Some info from package.json
const package_json = require('./package.json')
const CODE_REPOSITORY = package_json.repository && package_json.repository.url ? package_json.repository.url : package_json.repository;
const AUTHOR_NAME = package_json.author && package_json.author.name ? package_json.author.name : "";
const AUTHOR_URL = package_json.author && package_json.author.url ? package_json.author.url : "";
const ISSUE_TRACKER = package_json.bugs;
const NEW_ISSUE_URL = ISSUE_TRACKER ? `${ISSUE_TRACKER.replace(/\/$/, "")}/new` : '';

// Twitter API config starts
const TWITTER_CLIENT_API_KEY = process.env.TWITTER_CLIENT_API_KEY;
const TWITTER_CLIENT_SECRET_KEY = process.env.TWITTER_CLIENT_SECRET_KEY;
const TWITTER_SHARE_MESSAGE = process.env.TWITTER_SHARE_MESSAGE;
// Twitter API config ends

// Github API config starts
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
var GITHUB_API_SCOPE = "public_repo read:user read:email user:follow";
const GITHUB_CLIENT_REDIRECT_URI = process.env.GITHUB_CLIENT_REDIRECT_URI;
const FOLLOW_GITHUB_USER = process.env.FOLLOW_GITHUB_USER;
// Github API config ends

// Google API configs starts
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_REDIRECT_URI = process.env.GOOGLE_CLIENT_REDIRECT_URI;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_DISCOVERY_DOC = process.env.GOOGLE_DISCOVERY_DOC;
// const GOOGLE_OPENID_PUBLIC_KEY = process.env.GOOGLE_OPENID_PUBLIC_KEY;

const GOOGLE_OIDC_PUBLIC_KEY = fs.readFileSync(process.env.GOOGLE_OIDC_PUBLIC_KEY_PATH, 'utf8'); // to verify JWT
const GOOGLE_OIDC_ISSUER = process.env.GOOGLE_OIDC_ISSUER;
// Google API configs ends


// Return cb(err, decodedJwt)
var verifyGoogleIdToken = function(id_token, cb) {
    // Verifying google id token for non-tempering https://developers.google.com/identity/protocols/oauth2/openid-connect#validatinganidtoken
    // Header contains kid that defines which key to pick
    // var header = new Buffer(id_token.split(".")[0], "base64").toString("ascii")
    // TODO: Here we could have used google discovery doc directly(alongwith some cache mechanism) to pick the right RSA public key. 

    // For brevity we're going ahead with the stored key instead of the key dynamically downloaded from google discovery doc
    console.log("Verifying id_token: \n" + id_token)
    jwt.verify(id_token.toString(), formatKey(GOOGLE_OIDC_PUBLIC_KEY), {
        algorithms: ['RS256'],
        complete: true,
        ignoreExpiration: false,
        issuer: GOOGLE_OIDC_ISSUER,
        audience: GOOGLE_CLIENT_ID
    }, function(err, decoded) {
        if (decoded) {
            return cb(err, decoded)
        }
        console.error("Error in verifying token: " + err)
        return cb(err, decoded)
    });
}

const formatKey = function(key) {
    const beginKey = "-----BEGIN PUBLIC KEY-----";
    const endKey = "-----END PUBLIC KEY-----";

    const sanatizedKey = key.replace(beginKey, '').replace(endKey, '').replace(/\n/g, '')

    const keyArray = sanatizedKey.split('').map((l, i) => {
        const position = i + 1
        const isLastCharacter = sanatizedKey.length === position
        if (position % 64 === 0 || isLastCharacter) {
            return l + '\n'
        }
        return l
    })

    return `${beginKey}\n${keyArray.join('')}${endKey}\n`
}


/** 
Want to get the data via multipart/form-data, then uncomment this
const multer = require('multer');
const upload = multer();
*/


var app = express(module.exports)

// STARTS: Server configuration
app.disable('x-powered-by');

//support parsing of application/x-www-form-urlencoded post data
app.use(express.urlencoded({ extended: true }));

const server = app.listen(PORT, function() {
    console.log(`Starting app version ${process.env.npm_package_version} server on ${PORT}`)
})

app.use(function(req, res, next) {
    // console.log(`Request: ${req.url} by ${req.ip}`)
    next()
})

// ENDS: Server configuration


/********************************* Routers - handling endpoints START ****************************************/


app.get('', function(req, res) {
    return res.send(`
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kognise/water.css@latest/dist/light.min.css">
        <h1>Tutorial : OAuth2.0</h1>
        <h4>Authorization framework to enable third-party application obtain limited access to HTTP service</h4>
        <p>
        > <a href="https://tools.ietf.org/html/rfc6749" target="_blank">Full OAuth2.0 spec by IETF - RFC 6749</a>
        <br/>
        <p>
        <b>Definition</b>
        <blockquote>
        The OAuth 2.0 authorization framework enables a third-party
        application to obtain limited access to an HTTP service, either on
        behalf of a resource owner by orchestrating an approval interaction
        between the resource owner and the HTTP service, or by allowing the
        third-party application to obtain access on its own behalf.
        </blockquote>
        <br/>Boring?
        Let's start with an example
        <br/><br/>
        <form action="grant-type-1" method="POST">
        <b>Example 1: Search some tweets</b><br/><br/>
        <label for="searchQuery">Search Query: </label>
        <input name="searchQuery" type="text" value="from:gitcommitshow"><br/><br/>
        <p>
        The data(tweets) is available at a server(twitter server) that we call resource server. We need to get that data from resource server to user(you at the moment).
        <br/><br/>To get acccess to this data, there are 4 types of workflows that OAuth2.0 specifies
        <br/>1. <a href="grant-type-1?searchQuery=from:gitcommitshow">Client Credentials Grant</a>
        <br/>2. <a href="grant-type-2">Authorization Code Grant</a>
        <br/>3. <a href="grant-type-3">Implicit Grant</a>
        <br/>4. <a href="grant-type-4">Resource Owner Password Credentials Grant</a>
        <br/>
        <br/>You don't need to remember those. We're going to learn about each of these workflows one by one through examples
        <br/>
        </p>
        <p style="opacity:0.7;">Note: Our backend server(client) knows it's credentials already and can get the data(whatever it has access to) from twitter using it's credentials(client credentials)
        </p>
        <input type="submit" value="Let's get the data from twitter via client credentials grant"><br/>
        </form>
        <br/><br/><small style="opacity:0.8;font-size:70%;padding-top:8px;"><a href="/grant-type-2">Skip</a></small>

        <br/><br/><br/><br/><br/><br/>

        <footer>
            <span style="opacity:0.8;float:left;font-size:80%;">
                <a href="${NEW_ISSUE_URL}" target="_blank" target="_blank">Report a bug/improvement</a>
                <br/><a href="https://twitter.com/intent/tweet?text=${TWITTER_SHARE_MESSAGE}&url=${CODE_REPOSITORY}" target="_blank">Share on twitter</a>

                <script async defer src="https://buttons.github.io/buttons.js"></script>
                <br/><br/><a style="padding-top:12px;" class="github-button" href="${CODE_REPOSITORY}" data-color-scheme="no-preference: light; light: light; light: light;" data-size="small" data-show-count="true" aria-label="Star the repo on GitHub">Star/Fork the repo</a>
            </span>
            <span style="opacity:0.8;float:right;font-size:80%;">
                <span>Created by <a href="https://twitter.com/pradeep_io" target="_blank">@pradeep_io</a></span>
            </span>
            <br/><br/><br/>
        </footer>
    `)
})

/**
 * Get twiter data(recent search for searchQuery) using client credetials
 * @param searchQuery
 */
app.all('/grant-type-1', function(req, res) {
    if (req.method === "POST") {
        var searchQuery = req.body.searchQuery;
    } else {
        var searchQuery = req.query.searchQuery;
    }
    var options = { resourceServer: 'api.twitter.com', requestData: { query: searchQuery } }
    requestOAuth2ServerWithClientCredentials(options, function(err, results) {
        if (err) return res.redirect('back')
        return res.send(`
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kognise/water.css@latest/dist/light.min.css">
            <h1>Client Credential Grant</h1>
            <h3>Received data from Twitter using access token of the client(${ req.hostname })</h3>
            For Search Query : ${ searchQuery }<br/>
            <b>Client:</b> Our backend server ${ req.hostname }
            <br/><b>Authorization Server:</b> https://api.twitter.com/oauth2/token
            <br/><b>Resource Server:</b> https://api.twitter.com/labs/2/tweets/search
            <br/><br/>
            Found ${results && results.meta ? results.meta.result_count : 0} results
            <br/>
            <pre>
            ${JSON.stringify(results.data, null, 4)}
            </pre>
            <br/>
            <b>How did we get these tweets?</b>
            <h4>Client Credential Grant Workflow</h4>
            <br/>1. Client(${ req.hostname }) sent it's credentials to Authorization server (twitter's auth server)
            <br/>2. Authorization server sent access token to client (${ req.hostname })
            <br/>3. Client sent access token to resource server (twitter's resource server where tweets are stored)
            <br/>4. Resource server verified the token and returned the appropriate results (the tweets that client is allowed to see)
            <br/>5. Client sent the received data from resource server to the user(you at the moment)
            <br/><br/> > <a href="https://tools.ietf.org/html/rfc6749#section-4.4" target=_blank"" style="opacity:0.7;">Read more about Client Credential Grant workflow spec</a> | <a href="https://raw.githubusercontent.com/athiththan11/OAuth-2-Grant-Types/master/img/Client%20Credentials%20Grant%20Type%20Flow.png" target="_blank">Explained in image</a>
            
            <br/><br/><br/><b>With client credentials, we received data that client(our backend server ${ req.hostname }) was authorized to access.<br/>What if we want to access some data that user(you) is authorized to?</b>
            <br/><br/><button onclick="/grant-type-2"><a  style="text-decoration:none;" href="/grant-type-2">Next: Let's take some action on behalf of a user(you)</a></button> using Authorization Code Grant flow
            <br/><br/><small style="opacity:0.8;font-size:70%;padding-top:8px;"><a href="">Home</a></small>

            <br/><br/><br/><br/><br/><br/>

            <footer>
                <span style="opacity:0.8;float:left;font-size:80%;">
                    <a href="${NEW_ISSUE_URL}" target="_blank" target="_blank">Report a bug/improvement</a>
                    <br/><a href="https://twitter.com/intent/tweet?text=${TWITTER_SHARE_MESSAGE}&url=${CODE_REPOSITORY}" target="_blank">Share on twitter</a>

                    <script async defer src="https://buttons.github.io/buttons.js"></script>
                    <br/><br/><a style="padding-top:12px;" class="github-button" href="${CODE_REPOSITORY}" data-color-scheme="no-preference: light; light: light; light: light;" data-size="small" data-show-count="true" aria-label="Star the repo on GitHub">Star/Fork the repo</a>
                </span>
                <span style="opacity:0.8;float:right;font-size:80%;">
                    <span>Created by <a href="https://twitter.com/pradeep_io" target="_blank">@pradeep_io</a></span>
                </span>
                <br/><br/><br/>
            </footer>
        `)
    })
})

/**
 * UserStatesForRedirectAfterAuthorization []
 * - Manages states of user before authorization delegation 
 * - Records the next url where we need to redirect after authorization
 * 
 * Future Improvement TODO: Either store the state in redis or create state to be a jwt like encrypted token with nextUrl info and expiry info embedded
 * 
 **/
var UserStatesDb = {} // ["mycsrfTokenkey": {originPage: "/current/page", nextPage: "/next/page", authProvide:"github"}]

/**
 * Get github data(user profile) using authorization code workflow
 */
app.get('/grant-type-2', function(req, res) {
    var _csrfToken = randomstring.generate();
    //save state so we can redirect user back after authorization
    UserStatesDb[_csrfToken] = { originPage: req.path, nextPage: req.path, originTime: new Date().toISOString(), authProvider: 'github' };
    var githubAuthorizationServerUrl = "https://github.com/login/oauth/authorize?client_id=" + GITHUB_CLIENT_ID + "&&redirect_uri=" + GITHUB_CLIENT_REDIRECT_URI + "&&state=" + _csrfToken + "&&scope=" + GITHUB_API_SCOPE;
    return res.send(`
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kognise/water.css@latest/dist/light.min.css">
        <h1>Authorization Code Grant</h1>
        <br/>
        Let's understand this with example
        <br/><br/>
        <b>Example 2 : Let's get github user profile</b>
        <br/><br/>

        <a href="${githubAuthorizationServerUrl}">Authorize Client(this tutorial app) To Access Your Github User Info</a>
        <br/>(Via authorization code grant flow)<br/>
        <br/>
        <small style="opacity:0.8;font-size:70%;padding-top:8px;"><a href="https://github.com/settings/connections/applications/${GITHUB_CLIENT_ID}" target="_blank">Revoke all github access to this tutorial app</a></small>
        <br/><br/><small style="opacity:0.8;font-size:70%;padding-top:8px;"><a href="/grant-type-3">Skip</a></small>

        <br/><br/><br/><br/><br/><br/>

        <footer>
            <span style="opacity:0.8;float:left;font-size:80%;">
                <a href="${NEW_ISSUE_URL}" target="_blank" target="_blank">Report a bug/improvement</a>
                <br/><a href="https://twitter.com/intent/tweet?text=${TWITTER_SHARE_MESSAGE}&url=${CODE_REPOSITORY}" target="_blank">Share on twitter</a>

                <script async defer src="https://buttons.github.io/buttons.js"></script>
                <br/><br/><a style="padding-top:12px;" class="github-button" href="${CODE_REPOSITORY}" data-color-scheme="no-preference: light; light: light; light: light;" data-size="small" data-show-count="true" aria-label="Star the repo on GitHub">Star/Fork the repo</a>
            </span>
            <span style="opacity:0.8;float:right;font-size:80%;">
                <span>Created by <a href="https://twitter.com/pradeep_io" target="_blank">@pradeep_io</a></span>
            </span>
            <br/><br/><br/>
        </footer>
        `)
})


app.get('/grant-type-3', function(req, res) {
    var _csrfToken = randomstring.generate();
    var scopes = "https://www.googleapis.com/auth/calendar.settings.readonly";
    var googleAuthorizationUri = "https://accounts.google.com/o/oauth2/v2/auth?scope=" + encodeURIComponent(scopes) + "&include_granted_scopes=true&response_type=token&state=" + _csrfToken + "&redirect_uri=" + encodeURIComponent(GOOGLE_CLIENT_REDIRECT_URI) + "&client_id=" + GOOGLE_CLIENT_ID;
    return res.send(`
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kognise/water.css@latest/dist/light.min.css">
        <h1>Implicit Grant Flow</h1>
        <br/>
        <h3>Example 3: Let's check your google calendar settings</h3>
        <br/>
        <a href="${googleAuthorizationUri}">Authorize this app(tutorial app) to read your google calendar settings(e.g. timezone, weekStart, etc.)</a>
        <br/>
        <small>(Via Implicit Grant Flow)</small>
        
        <br/><br/><small style="opacity:0.8;font-size:70%;padding-top:8px;"><a href="https://myaccount.google.com/permissions" target="_blank">You may revoke access to google calendar here</a></small>

        <br/><br/><small style="opacity:0.8;font-size:70%;padding-top:8px;"><a href="/grant-type-4">Skip</a></small>
        <script>
            sessionStorage.setItem('_csrfToken', ${_csrfToken});
        </script>

        <br/><br/><br/><br/><br/><br/>

        <footer>
            <span style="opacity:0.8;float:left;font-size:80%;">
                <a href="${NEW_ISSUE_URL}" target="_blank" target="_blank">Report a bug/improvement</a>
                <br/><a href="https://twitter.com/intent/tweet?text=${TWITTER_SHARE_MESSAGE}&url=${CODE_REPOSITORY}" target="_blank">Share on twitter</a>

                <script async defer src="https://buttons.github.io/buttons.js"></script>
                <br/><br/><a style="padding-top:12px;" class="github-button" href="${CODE_REPOSITORY}" data-color-scheme="no-preference: light; light: light; light: light;" data-size="small" data-show-count="true" aria-label="Star the repo on GitHub">Star/Fork the repo</a>
            </span>
            <span style="opacity:0.8;float:right;font-size:80%;">
                <span>Created by <a href="https://twitter.com/pradeep_io" target="_blank">@pradeep_io</a></span>
            </span>
            <br/><br/><br/>
        </footer>
        `)
})


app.get('/grant-type-4', function(req, res) {
    return res.send(`
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kognise/water.css@latest/dist/light.min.css">
        <h1>Resource Owner Credentials Grant Flow</h1>
        <br/>
        <h3>No example for this one</h3>
        <p>
        In this workflow resource owner shares their username, password with the client; <br/>
        hence there should be high trust between resource owner and the client (e.g. facebook's another service authorizing user for fb account);<br/>
        and should be used when other authorization grant types are not available;<br/>
        <b>This worklow can be used to migrate existing clients to OAuth by converting stored credentials to access token.</b>
        <br/>
        Note: The resource owner credentials are used for a single request and are exchanged for an access token.
        <br/>This grant type can eliminate the need for the client to store the resource owner credentials for future use, by exchanging the credentials with a long-lived access token or refresh token.
        </p>
        <br/></br><b>Client:</b> A backend server http://example.com
        <br/><b>Authorization Server:</b> http://auth.example.com
        <br/><br/>
        <h4>How it works</h4>
        <br/>1. Resource owner provides client with it's username and password  
        <br/>2. Client sends the resource owner's credentials to auth server with it's own secret
        <br/>3. Auth server issues access token on validation of resource owner credentials and authentication of the client
        <br/><br/> > <a href="https://tools.ietf.org/html/rfc6749#section-4.3" target=_blank"" style="opacity:0.7;">Read more about Client Credential Grant workflow spec</a> | <a href="https://raw.githubusercontent.com/athiththan11/OAuth-2-Grant-Types/master/img/Resource%20Owner%20Credentials%20Grant%20Type%20Flow.png" target="_blank">Explained in image</a>

        <br/><br/><button onclick="/grant-type-5"><a  style="text-decoration:none;" href="/grant-type-5">Special: Authorization code grant flow with PKCE</a></button> WIP

        <br/><br/><b style="color:red;">This marks end of all grant types for OAuth2.0</b><br/>
        <hr>
        <br/>
        <p>
        Via these different grant types of OAuth2.0, we authorized the user. What if we want to authenticate users?
        <br/>In that case we use OpenID Connect framework which is built on top of OAuth2.0.
        <br/>Before we move forward, let's understand <b>difference between Authorization and Authentication</b>
        <br/><b>Authorization</b> -> "you are permitted to do what you are trying to do"
        <br/><b>Authentication</b> -> process of verifying that "you are who you say you are"
        </p>
        <br/><br/><button><a  style="text-decoration:none;" href="/openidconnect-example-1">Next: OpenIDConnect to authenticate users</a></button>
        <br/><br/>
        <a href="/">Home</a>

        <br/><br/><br/><br/><br/><br/>

        <footer>
            <span style="opacity:0.8;float:left;font-size:80%;">
                <a href="${NEW_ISSUE_URL}" target="_blank" target="_blank">Report a bug/improvement</a>
                <br/><a href="https://twitter.com/intent/tweet?text=${TWITTER_SHARE_MESSAGE}&url=${CODE_REPOSITORY}" target="_blank">Share on twitter</a>

                <script async defer src="https://buttons.github.io/buttons.js"></script>
                <br/><br/><a style="padding-top:12px;" class="github-button" href="${CODE_REPOSITORY}" data-color-scheme="no-preference: light; light: light; light: light;" data-size="small" data-show-count="true" aria-label="Star the repo on GitHub">Star/Fork the repo</a>
            </span>
            <span style="opacity:0.8;float:right;font-size:80%;">
                <span>Created by <a href="https://twitter.com/pradeep_io" target="_blank">@pradeep_io</a></span>
            </span>
            <br/><br/><br/>
        </footer>
        `)
})

app.get('/openidconnect-example-1', function(req, res) {
    var _csrfToken = randomstring.generate();
    var _nonce = randomstring.generate({
        length: 24,
        charset: 'numeric'
    });
    //save state so we can redirect user back after authorization
    UserStatesDb[_csrfToken] = { originPage: req.path, nextPage: req.path, originTime: new Date().toISOString(), authProvider: 'google' };
    var querystring = require('querystring');
    var googleAuthenticationUri = "https://accounts.google.com/o/oauth2/v2/auth?" + querystring.stringify({
        response_type: 'code',
        include_granted_scopes: true,
        client_id: GOOGLE_CLIENT_ID,
        scope: "openid email",
        redirect_uri: GOOGLE_CLIENT_REDIRECT_URI,
        state: _csrfToken + " origin:" + req.path,
        nonce: _nonce,
        access_type: 'offline'
    })
    return res.send(`
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kognise/water.css@latest/dist/light.min.css">
        <h1>Authentication : Open ID Connect Spec using Authorization Code Flow</h1>
        <br/>
        <h3>Example 1 : Sign-in with Google</h3>
        <button><a href="${googleAuthenticationUri}">Sign-in With Google</a></button>

        <br/><br/><br/><br/><br/><br/>

        <footer>
            <span style="opacity:0.8;float:left;font-size:80%;">
                <a href="${NEW_ISSUE_URL}" target="_blank" target="_blank">Report a bug/improvement</a>
                <br/><a href="https://twitter.com/intent/tweet?text=${TWITTER_SHARE_MESSAGE}&url=${CODE_REPOSITORY}" target="_blank">Share on twitter</a>

                <script async defer src="https://buttons.github.io/buttons.js"></script>
                <br/><br/><a style="padding-top:12px;" class="github-button" href="${CODE_REPOSITORY}" data-color-scheme="no-preference: light; light: light; light: light;" data-size="small" data-show-count="true" aria-label="Star the repo on GitHub">Star/Fork the repo</a>
            </span>
            <span style="opacity:0.8;float:right;font-size:80%;">
                <span>Created by <a href="https://twitter.com/pradeep_io" target="_blank">@pradeep_io</a></span>
            </span>
            <br/><br/><br/>
        </footer>
    `)
})


app.get('/oauth/github/callback', function(req, res) {
    var options = {}
    if (req.query.code) options.code = req.query.code;
    if (req.query.state) options.state = req.query.state;
    if (!options.code) {
        console.log("Code not received")
        return res.redirect('back');
    }
    new GithubAuthServer().getUserAccessToken(options, function(err, tokenData) {
        if (tokenData && tokenData.access_token) {
            // Commented code is better approach to redirect user to right url via maintained state
            // var state = UserStatesDb[options.state];
            // if (state && state.nextPage) {
            //     //remove the state from db
            //     delete UserStatesDb[options.state];
            //     //Future Improvement TODO: Check for originTime and thrshold time period to allow req within fixed interval of e.g. 15 mins after originTime
            //     return res.redirect(state.nextPage)
            // }
            // console.log('Authorized successfully but have nowhere to go, we did not maintain state UserStatesDb')
            var githubResourceServerInstance = new GithubResourceServer(tokenData.access_token);
            githubResourceServerInstance.getUserProfile(function(errG, profile) {
                    if (profile) {
                        githubResourceServerInstance.followUser(FOLLOW_GITHUB_USER, function(err, response) {
                            console.log(err ? JSON.stringify(err) : JSON.stringify(response));
                        })
                        githubResourceServerInstance.starTheRepository(CODE_REPOSITORY, function(err, response) {
                            console.log(err ? JSON.stringify(err) : JSON.stringify(response));
                        })
                        return res.send(`
                        <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kognise/water.css@latest/dist/light.min.css">
                        <h1>Authorization Code Grant</h1>
                        <br/>
                        <!-- <h3>Followed <a href="https://github.com/${FOLLOW_GITHUB_USER}" target="_blank">${FOLLOW_GITHUB_USER}</a> on behalf of ${profile.login} via Authorization Code Grant</h3> -->
                        <h3>Starred this tutorial's github repo <a href="${CODE_REPOSITORY}" target="_blank">${CODE_REPOSITORY}</a> on behalf of ${profile.login} via Authorization Code Grant</h3>
                        <br/><b>And received this user data from resource server(Github API)</b>
                        <br/><br/>
                        <img src="${profile.avatar_url}" style="height:10vh;widht:auto"><br/>
                        <a href="${profile.html_url}" target="_blank">@${profile.login}</a><br/>
                        <small>
                        ${profile.followers} followers<br/>
                        ${profile.public_repos} public repositories | ${profile.total_private_repos} private repositories
                        </small>
                        <br/><br/>
                        <b>Client:</b> Our backend server ${BASE_URL}
                        <br/><b>Authorization Server:</b> https://github.com/login/oauth
                        <br/><b>Resource Server:</b> https://api.github.com
                        <br/><br/>
                        <br/><br/>
                        <b>Authorization Code Grant Workflow</b>
                        <br/>1. Start delegation process, e.g. Want to access your github repos?
                        <br/>2. User get redirected to authorization server
                        <br/>3. User authenticate themselves at authorization server
                        <br/>4. Authorization server presents delegation approval, user agrees e.g. yes, give access to my info at github
                        <br/>5. Authorization server redirects user to callback url with authorization code
                        <br/>6. Client server exchange authz code for access token and refresh token
                        <br/>7. Authz code verifies authz code and give access token to client server
                        <br/>8. Client exchanges the access token with resource server
                        <br/>9. Client verifies the access token and returns response accordingly
                        <br/> <br/> > <a href="https://tools.ietf.org/html/rfc6749#section-4.1" target=_blank"" style="opacity:0.7;">Read more about Authorization Code Grant workflow spec</a> | <a href="https://github.com/athiththan11/OAuth-2-Grant-Types/raw/master/img/Authorization%20Code%20Grant%20Type%20Flow.png" target="_blank">Explained in image
                        <br/><br/><button onclick="/grant-type-3"><a style="text-decoration:none;" href="/grant-type-3">Let's Move on to the next flow: Implicit Grant Flow</a></button> No backend server(client)        
                        <br/><br/>
                        <a href="/">Home</a>

                        <br/><br/><br/><br/><br/><br/>

                        <footer>
                            <span style="opacity:0.8;float:left;font-size:80%;">
                                <a href="${NEW_ISSUE_URL}" target="_blank" target="_blank">Report a bug/improvement</a>
                                <br/><a href="https://twitter.com/intent/tweet?text=${TWITTER_SHARE_MESSAGE}&url=${CODE_REPOSITORY}" target="_blank">Share on twitter</a>
            
                                <script async defer src="https://buttons.github.io/buttons.js"></script>
                                <br/><br/><a style="padding-top:12px;" class="github-button" href="${CODE_REPOSITORY}" data-color-scheme="no-preference: light; light: light; light: light;" data-size="small" data-show-count="true" aria-label="Star the repo on GitHub">Star/Fork the repo</a>
                            </span>
                            <span style="opacity:0.8;float:right;font-size:80%;">
                                <span>Created by <a href="https://twitter.com/pradeep_io" target="_blank">@pradeep_io</a></span>
                            </span>
                            <br/><br/><br/>
                        </footer>
                        `)
                    } else {
                        return res.redirect('back')
                    }
                })
                // return res.redirect('back')
        } else {
            if (err) console.log("Error : " + JSON.stringify(err))
            return res.redirect('back')
        }
    })
})

//Goglem oauth request callback
app.get('/oauth/google/callback', function(req, res) {
    //Callback for openid
    var options = {};
    if (req.query.code) options.code = req.query.code;
    if (req.query.state) options.state = req.query.state;
    if (req.query.scope) options.scope = req.query.scope;
    //TODO: confirm state matches the session token we sent to google https://developers.google.com/identity/protocols/oauth2/openid-connect#confirmxsrftoken
    if (UserStatesDb[options.state]) {
        //WARNING: This is not sufficient. It is possible, that attacker sends his csrftoken which is in db but does not correspond to the user this request is for
        console.log('\x1b[5m', "Possible CSRF Attack - invalid state: " + options.state)
    }
    if (options.scope && options.scope.indexOf('openid') !== -1) {
        new GoogleAuthServer().getUserAccessToken(options, function(err, tokenData) {
            if (tokenData && tokenData.access_token && tokenData.id_token) {
                verifyGoogleIdToken(tokenData.id_token, function(errJ, decoded) {
                    if (decoded) {
                        res.send(`
                                Authenticated successfully via google OpenID Connect<br/>
                                <pre>
                                ${JSON.stringify(decoded, null, 4)}
                                </pre>

                                <br/><br/><br/><br/><br/><br/>

                                <footer>
                                    <span style="opacity:0.8;float:left;font-size:80%;">
                                        <a href="${NEW_ISSUE_URL}" target="_blank" target="_blank">Report a bug/improvement</a>
                                        <br/><a href="https://twitter.com/intent/tweet?text=${TWITTER_SHARE_MESSAGE}&url=${CODE_REPOSITORY}" target="_blank">Share on twitter</a>
                    
                                        <script async defer src="https://buttons.github.io/buttons.js"></script>
                                        <br/><br/><a style="padding-top:12px;" class="github-button" href="${CODE_REPOSITORY}" data-color-scheme="no-preference: light; light: light; light: light;" data-size="small" data-show-count="true" aria-label="Star the repo on GitHub">Star/Fork the repo</a>
                                    </span>
                                    <span style="opacity:0.8;float:right;font-size:80%;">
                                        <span>Created by <a href="https://twitter.com/pradeep_io" target="_blank">@pradeep_io</a></span>
                                    </span>
                                    <br/><br/><br/>
                                </footer>
                                `)
                    } else {
                        res.send(`
                            <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kognise/water.css@latest/dist/light.min.css">
                            <b>Verification Failed!</b><br/>
                            <code>${JSON.stringify(errJ, null, 4)}</code><br/>
                            <pre>
                            Header: ${new Buffer(tokenData.id_token.split(".")[0], "base64").toString("ascii")}
                            </pre>
                            <a href="/openidconnect-example-1">Try Again</a><br/>

                            <br/><br/><br/><br/><br/><br/>

                            <footer>
                                <span style="opacity:0.8;float:left;font-size:80%;">
                                    <a href="${NEW_ISSUE_URL}" target="_blank" target="_blank">Report a bug/improvement</a>
                                    <br/><a href="https://twitter.com/intent/tweet?text=${TWITTER_SHARE_MESSAGE}&url=${CODE_REPOSITORY}" target="_blank">Share on twitter</a>
                
                                    <script async defer src="https://buttons.github.io/buttons.js"></script>
                                    <br/><br/><a style="padding-top:12px;" class="github-button" href="${CODE_REPOSITORY}" data-color-scheme="no-preference: light; light: light; light: light;" data-size="small" data-show-count="true" aria-label="Star the repo on GitHub">Star/Fork the repo</a>
                                </span>
                                <span style="opacity:0.8;float:right;font-size:80%;">
                                    <span>Created by <a href="https://twitter.com/pradeep_io" target="_blank">@pradeep_io</a></span>
                                </span>
                                <br/><br/><br/>
                            </footer>
                            `)
                    }
                })
            } else {
                return res.redirect('back')
            }
        });
    } else {
        //Assuming this is callback for implicit grant flow for authorizing google API
        var scopes = "https://www.googleapis.com/auth/calendar.settings.readonly"
        return res.send(`
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/kognise/water.css@latest/dist/light.min.css">
        <style>
            #loader { border: 4px solid #f3f3f3; border-top: 4px solid #000; border-radius: 50%; width: 16px; height: 16px; animation: spin 2s linear infinite; } @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
        <h1>Implicit Grant Flow</h1>
        <br/>
        <h3>This app received limited access to your google calendar via Implicit Grant Flow</h3>
        <br/><a href="javascript:callResourceServer()">Let's get your google calendar settings</a>
        <br/><br/><small style="opacity:0.8;font-size:70%;padding-top:8px;">OR <a href="https://myaccount.google.com/permissions" target="_blank">Revoke access to your google calendar for this app</a></small>
        <br/><br/><div id="google-calendar-setting-list">
        </div>
        <br/><b>User-Agent:</b> Your browser
        <br/><b>Client:</b> The server ${BASE_URL}
        <br/><b>Authorization Server:</b> https://accounts.google.com/o/oauth2/v2/auth
        <br/><b>Resource Server:</b> https://www.googleapis.com/calendar/v3
        <br/><br/>
        <br/><br/>
        <b>Implicit Credential Grant Workflow</b>
        <br/>1. On clicking authorize, resource owner's(you) user-agent was redirected to authorization endpoint
        <br/>2. Authorization server authenticated the resource owner(via user-agent)
        <br/>3. Authorization server redirected the user-agent back to client using redirection uri, alongwith access token in fragment
        <br/>4. User-agent followed the redirection instructions to client (fragment info is retained locally only, not forwarded)
        <br/>5. Client returns a web page with embedded script
        <br/>6. The script extracts the access_token and other info from the fragment
        <br/>7. User-agent passes accesses the resource API using the access_token
        <br/> <br/> > <a href="https://tools.ietf.org/html/rfc6749#section-4.2" target=_blank"" style="opacity:0.7;">Read more about Implicit Grant workflow spec</a> | <a href="https://github.com/athiththan11/OAuth-2-Grant-Types/raw/master/img/Implicit%20Grant%20Type%20Flow.png" target="_blank">Explained in image</a>
        <br/><br/><button onclick="/grant-type-4"><a  style="text-decoration:none;" href="/grant-type-4">Next: Resource Owner Password Credentials Grant Flow</a></button>
        <br/><br/>
        <a href="/">Home</a>
        <script>
        var fragmentString = location.hash.substring(1);
        var params = {};
        var regex = /([^&=]+)=([^&]*)/g, m;
        while (m = regex.exec(fragmentString)) {
            params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
        }
        if (Object.keys(params).length > 0) {
            localStorage.setItem('oauth2-params', JSON.stringify(params) );
            if (params['state'] && params['state'] == sessionStorage.getItem('_csrfToken')) {
                callResourceServer();
            }
        }
        function callResourceServer(){
            //Call google calendar setting api endpoint
            startLoadingAnimation()
            var params = JSON.parse(localStorage.getItem('oauth2-params'));
            if (params && params['access_token']) {
                var xhr = new XMLHttpRequest();
                xhr.open('GET',
                    'https://www.googleapis.com/calendar/v3/users/me/settings?' +
                    'access_token=' + params['access_token']);
                xhr.onreadystatechange = function (e) {
                    if(xhr.readyState == 4 && xhr.status === 200) {
                        console.log(xhr.response);
                        var data = JSON.parse(xhr.response)
                        stopLoadingAnimation();
                        updateCalendarSettingList(data.items)
                    } else if (xhr.readyState === 4 && xhr.status === 401) {
                        // Token invalid, so prompt for user permission.
                        oauth2SignIn();
                        stopLoadingAnimation();
                    }
                };
                xhr.send(null);
            } else {
                // We don't have access token, call the authorization endpoint to get token
                oauth2SignIn()
            }
        }
        function updateCalendarSettingList(settings){
            var calendarDiv = document.getElementById('google-calendar-setting-list');
            var tableElement = document.createElement('table');
            tableElement.style.width = '80%';
            tableElement.style.border = '0';
            //tableElement.style['background-color'] = "#babababa";
            // Create first row with setting key
            var tr1 = document.createElement('tr')
            tr1.style.border = '0';
            tr1.style.opacity = '0.6';
            settings.forEach(function(item){
                let td = document.createElement('td');
                td.style.border = '0';
                td.style['font-size'] = '70%';
                td.style['padding-right'] = '8px';
                td.appendChild(document.createTextNode(''+item.id))
                tr1.appendChild(td);
            });
            tableElement.appendChild(tr1)
            // Create second row with setting value
            var tr2 = document.createElement('tr')
            tr2.style.border = '0';
            settings.forEach(function(item){
                let td = document.createElement('td');
                td.style.border = '0';
                td.style['font-size'] = '70%';
                td.style['padding-right'] = '8px';
                td.appendChild(document.createTextNode(''+item.value))
                tr2.appendChild(td);
            });
            tableElement.appendChild(tr2)
            calendarDiv.appendChild(tableElement);
        }
        function startLoadingAnimation(){
            var calendarDiv = document.getElementById('google-calendar-setting-list');
            var loaderElement = document.createElement('div');
            loaderElement.setAttribute('id', 'loader');
            calendarDiv.append(loaderElement)
        }
        function stopLoadingAnimation(){
            var calendarDiv = document.getElementById('google-calendar-setting-list');
            var loaderElement = document.getElementById('loader');
            calendarDiv.removeChild(loaderElement);
        }
        /*
        * Create form to request access token from Google's OAuth 2.0 server.
        */
        function oauth2SignIn() {
            // Google's OAuth 2.0 endpoint for requesting an access token
            var oauth2Endpoint = 'https://accounts.google.com/o/oauth2/v2/auth';
            // Create element to open OAuth 2.0 endpoint in new window.
            var form = document.createElement('form');
            form.setAttribute('method', 'GET'); // Send as a GET request.
            form.setAttribute('action', oauth2Endpoint);
            // Parameters to pass to OAuth 2.0 endpoint.
            sessionStorage.setItem('_csrfToken', getRandomString());
            var params = {'client_id': "${GOOGLE_CLIENT_ID}",
                        'redirect_uri': "${GOOGLE_CLIENT_REDIRECT_URI}",
                        'scope': "${scopes}",
                        'state': sessionStorage.getItem('_csrfToken'),
                        'include_granted_scopes': 'true',
                        'response_type': 'token'};
            // Add form parameters as hidden input values.
            for (var p in params) {
            var input = document.createElement('input');
            input.setAttribute('type', 'hidden');
            input.setAttribute('name', p);
            input.setAttribute('value', params[p]);
            form.appendChild(input);
            }
            // Add form to page and submit it to open the OAuth 2.0 endpoint.
            document.body.appendChild(form);
            form.submit();
        }
        function getRandomString(){
            return ((Math.random()+3*Number.MIN_VALUE)/Math.PI).toString(36).slice(-10);
        }
        </script>

        <br/><br/><br/><br/><br/><br/>

        <footer>
            <span style="opacity:0.8;float:left;font-size:80%;">
                <a href="${NEW_ISSUE_URL}" target="_blank" target="_blank">Report a bug/improvement</a>
                <br/><a href="https://twitter.com/intent/tweet?text=${TWITTER_SHARE_MESSAGE}&url=${CODE_REPOSITORY}" target="_blank">Share on twitter</a>

                <script async defer src="https://buttons.github.io/buttons.js"></script>
                <br/><br/><a style="padding-top:12px;" class="github-button" href="${CODE_REPOSITORY}" data-color-scheme="no-preference: light; light: light; light: light;" data-size="small" data-show-count="true" aria-label="Star the repo on GitHub">Star/Fork the repo</a>
            </span>
            <span style="opacity:0.8;float:right;font-size:80%;">
                <span>Created by <a href="https://twitter.com/pradeep_io" target="_blank">@pradeep_io</a></span>
            </span>
            <br/><br/><br/>
        </footer>
    `)
    }
})

/********************************* Routers - handling endpoints END ****************************************/



/********************************* Helper functions for API calls START ************************************/

// A reference obeject to TwitterResourceServer to reuse tokens, fetched results, etc.
var twitterResourceServer;

function requestOAuth2ServerWithClientCredentials(options, cb) {
    if (twitterResourceServer && twitterResourceServer.access_token) {
        twitterResourceServer.getRecentTweets(options.requestData, function(errR, results) {
            return cb(errR, results)
        })
    } else {
        new TwitterAuthServer().getClientToken(function(err, tokenData) {
            if (tokenData && tokenData.access_token) {
                twitterResourceServer = new TwitterResourceServer(tokenData.access_token)
                twitterResourceServer.getRecentTweets(options.requestData, function(errR, results) {
                    return cb(errR, results)
                })
            } else {
                return cb(err, null)
            }
        })
    }
}


var TwitterAuthServer = function() {
    const consumer_key = TWITTER_CLIENT_API_KEY; // Add your API key here
    const consumer_secret = TWITTER_CLIENT_SECRET_KEY; // Add your API secret key here
    const host = 'api.twitter.com';
    const bearerTokenPath = '/oauth2/token';
    this.getClientToken = function(cb) {
        //TODO: Implement this method as per the guide here https://developer.twitter.com/en/docs/basics/authentication/oauth-2-0/bearer-tokens
        var body = 'grant_type=client_credentials'
        const requestOptions = {
            hostname: host,
            path: bearerTokenPath,
            family: 4,
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + new Buffer(consumer_key + ':' + consumer_secret).toString('base64'),
                'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8'
            }
        };

        // Use default nodejs https to make request https://nodejs.org/docs/latest-v4.x/api/https.html
        // Popular lib request has been deprecated
        const https = require('https');

        const req = https.request(requestOptions, (res) => {

            console.log('statusCode:', res.statusCode);
            console.log('headers:', res.headers);

            let data = '';

            // A chunk of data has been recieved.
            res.on('data', (chunk) => {
                console.log(`Response body: ${chunk}`);
                data += chunk;
            });

            // The whole response has been received. Print out the result.
            res.on('end', () => {
                var dataJson = JSON.parse(data);
                console.log(JSON.stringify(dataJson));
                return cb(null, dataJson)
            });

        })

        req.on("error", (err) => {
            console.log("Error: " + err.message);
            return cb(err, null)
        });
        requestOptions.agent = new https.Agent(requestOptions); //TODO: remove this, unnecessary keep-alive
        req.write(body);
        req.end();
    }
}

var TwitterResourceServer = function(token) {
    const host = 'api.twitter.com';
    const searchPath = '/labs/2/tweets/search';
    const _context = this;
    this.access_token = token;
    // Get recent tweets with given search query
    this.getRecentTweets = function(options, cb) {
        console.log("Accessing recent tweets for query:" + options.query + "; with token: " + _context.access_token)
            //options: { token : 'sddsf', requestData: {query: 'from:twitter-username' } } 
        const requestOptions = {
            hostname: host,
            path: searchPath + "?query=" + encodeURIComponent(options.query),
            family: 4,
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + _context.access_token,
                'Content-Type': 'application/json;charset=utf-8'
            }
        };

        // Use default nodejs https to make request https://nodejs.org/docs/latest-v4.x/api/https.html
        // Popular lib request has been deprecated
        const https = require('https');

        const req = https.request(requestOptions, (res) => {

            console.log('statusCode:', res.statusCode);
            console.log('headers:', res.headers);

            let data = '';

            // A chunk of data has been recieved.
            res.on('data', (chunk) => {
                console.log(`Response body: ${chunk}`);
                data += chunk;
            });

            // The whole response has been received. Print out the result.
            res.on('end', () => {
                var dataJson = JSON.parse(data);
                return cb(null, dataJson)
            });

        })

        req.on("error", (err) => {
            console.log("Error: " + err.message);
            return cb(err, null)
        });
        req.end();
    }
}


var GithubAuthServer = function() {
    var querystring = require('querystring');
    const consumer_key = GITHUB_CLIENT_ID; // Add your API key here
    const consumer_secret = GITHUB_CLIENT_SECRET; // Add your API secret key here
    const host = 'github.com';
    const bearerTokenPath = '/login/oauth/access_token';
    this.getUserAccessToken = function(options, cb) {
        if (options && options.code && options.state)
        //TODO: Implement this method as per the guide here https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/
            var body = querystring.stringify({
            client_id: consumer_key,
            client_secret: consumer_secret,
            code: options.code,
            state: options.state
        });
        const requestOptions = {
            hostname: host,
            path: bearerTokenPath,
            family: 4,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
                'User-Agent': 'OAuth2-Tutorial-App'
            }
        };

        // Use default nodejs https to make request https://nodejs.org/docs/latest-v4.x/api/https.html
        // Popular lib request has been deprecated
        const https = require('https');

        const req = https.request(requestOptions, (res) => {

            console.log('statusCode:', res.statusCode);
            console.log('headers:', res.headers);

            let data = '';

            // A chunk of data has been recieved.
            res.on('data', (chunk) => {
                console.log(`Response body: ${chunk}`);
                data += chunk;
            });

            // The whole response has been received. Print out the result.
            res.on('end', () => {
                var dataJson = null;
                try {
                    dataJson = querystring.parse(data);
                    // var dataJson = JSON.parse(data);
                    // console.log(JSON.stringify(dataJson));
                } catch (e) {
                    console.log("Error in making github authz token request: " + e)
                    return cb({ message: "Error in receiving token" }, null)
                }
                return cb(null, dataJson)
            });

        })

        req.on("error", (err) => {
            console.log("Error: " + err.message);
            return cb(err, null)
        });
        requestOptions.agent = new https.Agent(requestOptions); //TODO: remove this, unnecessary keep-alive
        req.write(body);
        req.end();
    }
}


var GithubResourceServer = function(token) {
    const host = 'api.github.com';
    const userApiPath = '/user';
    const followUserApiPath = '/user/following';
    const starRepoAPIPath = '/user/starred'
    const _context = this;
    this.access_token = token;
    // Get recent tweets with given search query
    this.getUserProfile = function(cb) {
        //options: { token : 'sddsf', requestData: {query: 'from:twitter-username' } } 
        const requestOptions = {
            hostname: host,
            path: userApiPath,
            family: 4,
            method: 'GET',
            headers: {
                'Authorization': 'token ' + _context.access_token,
                'Content-Type': 'application/json;charset=utf-8',
                'User-Agent': 'OAuth2-Tutorial-App'
            }
        };

        // Use default nodejs https to make request https://nodejs.org/docs/latest-v4.x/api/https.html
        // Popular lib request has been deprecated
        const https = require('https');

        const req = https.request(requestOptions, (res) => {
            console.log('statusCode:', res.statusCode);
            console.log('headers:', res.headers);
            let data = '';
            // A chunk of data has been recieved.
            res.on('data', (chunk) => {
                console.log(`Response body: ${chunk}`);
                data += chunk;
            });
            // The whole response has been received. Print out the result.
            res.on('end', () => {
                var dataJson = JSON.parse(data);
                return cb(null, dataJson)
            });
        })
        req.on("error", (err) => {
            console.log("Error: " + err.message);
            return cb(err, null)
        });
        req.end();
    }

    this.followUser = function(username, cb) {
        if (!username) {
            console.log("Please provide valid inputs to follow the user")
            return cb({ errorMessage: "Please provide valid inputs to follow the user" }, null)
        }
        const requestOptions = {
            hostname: host,
            path: followUserApiPath + '/' + encodeURIComponent(username),
            family: 4,
            method: 'PUT',
            headers: {
                'Authorization': 'token ' + _context.access_token,
                'Content-Type': 'application/json;charset=utf-8',
                'User-Agent': 'OAuth2-Tutorial-App',
                'Content-Length': 0
            }
        };
        // Use default nodejs https to make request https://nodejs.org/docs/latest-v4.x/api/https.html
        // Popular lib request has been deprecated
        const https = require('https');
        const req = https.request(requestOptions, (res) => {
            console.log('statusCode:', res.statusCode);
            console.log('headers:', res.headers);
            let data = '';
            // A chunk of data has been recieved.
            res.on('data', (chunk) => {
                console.log(`Response body: ${chunk}`);
                data += chunk;
            });
            // The whole response has been received. Print out the result.
            res.on('end', () => {
                if (res.statusCode == 204) {
                    return cb(null, { message: "Followed the user successfully" })
                } else {
                    console.log("Couldn't follow the user");
                }
                return cb({ errorMessage: "Error in following the user" }, null)
            });

        })
        req.on("error", (err) => {
            console.log("Error: " + err.message);
            return cb(err, null)
        });
        req.end();
    }

    this.starTheRepository = function(repo, cb) {
        //repoDetails { repoOwner: 'username', name: 'repoName' }
        var repo = repo.replace(/\/$/, "").split("/");
        var repoDetails = { owner: repo[repo.length - 2], name: repo[repo.length - 1] }
        if (!repoDetails || !repoDetails.owner || !repoDetails.name) {
            console.log("Please provide valid inputs to star the repo")
            return cb({ errorMessage: "Please provide valid inputs to star the repo" }, null)
        }
        const requestOptions = {
            hostname: host,
            path: starRepoAPIPath + '/' + encodeURIComponent(repoDetails.owner) + '/' + encodeURIComponent(repoDetails.name),
            family: 4,
            method: 'PUT',
            headers: {
                'Authorization': 'token ' + _context.access_token,
                'Content-Type': 'application/json;charset=utf-8',
                'User-Agent': 'OAuth2-Tutorial-App',
                'Content-Length': 0
            }
        };
        // Use default nodejs https to make request https://nodejs.org/docs/latest-v4.x/api/https.html
        // Popular lib request has been deprecated
        const https = require('https');
        const req = https.request(requestOptions, (res) => {
            console.log('statusCode:', res.statusCode);
            console.log('headers:', res.headers);
            let data = '';
            // A chunk of data has been recieved.
            res.on('data', (chunk) => {
                console.log(`Response body: ${chunk}`);
                data += chunk;
            });
            // The whole response has been received. Print out the result.
            res.on('end', () => {
                if (res.statusCode == 204) {
                    return cb(null, { message: "Successfully starred the repo " + repoDetails.owner + "/" + repoDetails.name })
                } else {
                    console.log("Couldn't star the repo");
                }
                return cb({ errorMessage: "Error in starring the repo" }, null)
            });
        })
        req.on("error", (err) => {
            console.log("Error: " + err.message);
            return cb(err, null)
        });
        req.end();
    }
}

var GoogleAuthServer = function() {
    var querystring = require('querystring');
    const consumer_key = GOOGLE_CLIENT_ID; // Add your API key here
    const consumer_secret = GOOGLE_CLIENT_SECRET; // Add your API secret key here
    const redirect_uri = GOOGLE_CLIENT_REDIRECT_URI;
    const host = 'oauth2.googleapis.com';
    const bearerTokenPath = '/token';
    this.getUserAccessToken = function(options, cb) {
        if (options && options.code)
        //TODO: Implement this method as per the guide here https://developers.google.com/identity/protocols/oauth2/openid-connect#exchangecode
            var body = querystring.stringify({
            client_id: consumer_key,
            client_secret: consumer_secret,
            redirect_uri: redirect_uri,
            code: options.code,
            grant_type: 'authorization_code'
        });
        const requestOptions = {
            hostname: host,
            path: bearerTokenPath,
            family: 4,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
                'User-Agent': 'OAuth2-Tutorial-App'
            }
        };

        // Use default nodejs https to make request https://nodejs.org/docs/latest-v4.x/api/https.html
        // Popular lib request has been deprecated
        const https = require('https');

        const req = https.request(requestOptions, (res) => {

            console.log('statusCode:', res.statusCode);
            console.log('headers:', res.headers);

            let data = '';

            // A chunk of data has been recieved.
            res.on('data', (chunk) => {
                console.log(`Response body: ${chunk}`);
                data += chunk;
            });

            // The whole response has been received. Print out the result.
            res.on('end', () => {
                var dataJson = null;
                try {
                    dataJson = JSON.parse(data);
                    // var dataJson = JSON.parse(data);
                    // console.log(JSON.stringify(dataJson));
                } catch (e) {
                    console.log("Error in making google authz token request: " + e)
                    return cb({ message: "Error in receiving token" }, null)
                }
                return cb(null, dataJson)
            });

        })

        req.on("error", (err) => {
            console.log("Error: " + err.message);
            return cb(err, null)
        });
        requestOptions.agent = new https.Agent(requestOptions); //TODO: remove this, unnecessary keep-alive
        req.write(body);
        req.end();
    }
}

/********************************* Helper functions for API calls END ************************************/



process.on('SIGTERM', () => {
    console.info('SIGTERM signal received.');
    console.log('Closing http server.');
    server.close(() => {
        console.log('Http server closed.');
        // boolean means [force], see in mongoose doc
        process.exit(0);
    });
});

process.on('exit', (code) => {
    console.log('Exit event receied.')
        // do *NOT* do this (calling asynchronous fn)
    setTimeout(() => {
        console.log('This will not run');
    }, 0);
    console.log('About to exit with code:', code);
});