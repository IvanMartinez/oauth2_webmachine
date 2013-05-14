%% @author ivanmr
%% @doc @todo Add description to test_util.

-module(test_util).

-include_lib("webmachine/include/wm_reqdata.hrl").

-type(wm_reqdata() :: #wm_reqdata{}).


%% ====================================================================
%% API functions
%% ====================================================================
-export([make_get_wrq/3]).

-spec make_get_wrq(Path         :: string(),
                   Parameters   :: list({string(), string() | binary()}),
                   Headers      :: list({string(), string()})) ->
          wm_reqdata().
make_get_wrq(Path, [], Headers) ->
    wrq:create('GET', http, {1,1}, Path, mochiweb_headers:from_list(Headers));
make_get_wrq(Path, Parameters, Headers) ->
    wrq:create('GET', http, {1,1}, Path ++ "?" ++ 
                   mochiweb_util:urlencode(Parameters),
               mochiweb_headers:from_list(Headers)).
