%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc Callbacks for the oauth2_webmachine application.

-module(oauth2_webmachine_app).
-author('author <author@example.com>').

-behaviour(application).
-export([start/2,stop/1]).


%% @spec start(_Type, _StartArgs) -> ServerRet
%% @doc application start callback for oauth2_webmachine.
start(_Type, _StartArgs) ->
    oauth2_ets_backend:start(),
    oauth2_webmachine_sup:start_link().

%% @spec stop(_State) -> ServerRet
%% @doc application stop callback for oauth2_webmachine.
stop(_State) ->
    oauth2_ets_backend:stop(),
    ok.
