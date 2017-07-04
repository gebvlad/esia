# esia
A PHP client to a Russian government authentication system for persons. 
It uses a CodeIgniter 3 framework as infrastructure but can be easily adopted to a standalone behavior.
Provides an OAuth method in REST-API approach.
Key functionality: 
  requests an authorization code;
  requests an access token;
  checks the access token to comply with ESIA Recommendations (partially);
  requests ESIA for user data set defined both by the provided scope and access token.
Known problems: yet not performs an ESIA signature check required by Recommendations for OAuth method.
