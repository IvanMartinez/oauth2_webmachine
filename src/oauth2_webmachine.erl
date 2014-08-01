%% @author author <author@example.com>
%% @copyright YYYY author.

%% @doc oauth2_webmachine startup code

-module(oauth2_webmachine).
-author('author <author@example.com>').
-export([start/0, start_link/0, stop/0]).

ensure_started(App) ->
    case application:start(App) of
        ok ->
            ok;
        {error, {already_started, App}} ->
            ok
    end.

%% @spec start_link() -> {ok,Pid::pid()}
%% @doc Starts the app for inclusion in a supervisor tree
start_link() ->
    ensure_started(compiler),
    ensure_started(xmerl),
    ensure_started(syntax_tools),
    ensure_started(inets),
    ensure_started(crypto),
    ensure_started(asn1),
    ensure_started(public_key),
    ensure_started(ssl),
    ensure_started(oauth2),
    ensure_started(mochiweb),
    application:set_env(webmachine, webmachine_logger_module, 
                        webmachine_logger),
    ensure_started(webmachine),
    oauth2_webmachine_sup:start_link().

%% @spec start() -> ok
%% @doc Start the oauth2_webmachine server.
start() ->
    ensure_started(compiler),
    ensure_started(xmerl),
    ensure_started(syntax_tools),
    ensure_started(inets),
    ensure_started(crypto),
    ensure_started(asn1),
    ensure_started(public_key),
    ensure_started(ssl),
    ensure_started(oauth2),
    ensure_started(mochiweb),
    application:set_env(webmachine, webmachine_logger_module, 
                        webmachine_logger),
    ensure_started(webmachine),
    application:start(oauth2_webmachine).

%% @spec stop() -> ok
%% @doc Stop the oauth2_webmachine server.
stop() ->
    Res = application:stop(oauth2_webmachine),
    application:stop(webmachine),
    application:stop(mochiweb),
    application:stop(oauth2),
    application:stop(oauth2_ets_backend),
    application:stop(ssl),
    application:stop(public_key),
    application:stop(asn1),
    application:stop(crypto),
    application:stop(inets),
    application:stop(syntax_tools),
    application:stop(xmerl),
    application:stop(compiler),
    Res.
