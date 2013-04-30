-include_lib("webmachine/include/wm_reqdata.hrl").

-define(AUTHENTICATE_REALM, "oauth2_webmachine").

-type(wm_reqdata() :: #wm_reqdata{}).