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
    %% The ETS tables must be created here, in the main thread of the 
    %% application.
    oauth2_ets_backend:create(),
    oauth2_webmachine_sup:start_link().

%% @spec stop(_State) -> ServerRet
%% @doc application stop callback for oauth2_webmachine.
stop(_State) ->
    ok.
