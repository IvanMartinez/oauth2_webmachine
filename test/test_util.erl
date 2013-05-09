%% @author ivanmr
%% @doc @todo Add description to test_util.


-module(test_util).

-include("../include/oauth2_wrq.hrl").

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
make_get_wrq(Path, Params, Headers) ->
    wrq:create('GET', http, {1,1}, Path ++ "?" ++ 
                   mochiweb_util:urlencode(Params),
               mochiweb_headers:from_list(Headers)).
