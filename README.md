# esia
A PHP client to a Russian government person authentication system. It uses a CodeIgniter 3 framework as infrastructure but can be easily adopted to a standalone behavior.
Provides an OAuth method in REST-API approach.
Key functionality: requesting a authorization code; requesting an access token; checks access token in accordance with ESIA Recommendations; requesting ESIA user data set defined by the provided scope.
Known problems: yet not performs an ESIA signature check required for OAuth method.
