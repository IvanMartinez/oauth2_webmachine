%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Help functions for tests.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(test_util).

-include_lib("webmachine/include/wm_reqdata.hrl").

%% ====================================================================
%% API functions
%% ====================================================================

-export([make_get_wrq/3, make_post_wrq/3]).

-spec make_get_wrq(Path         :: string(),
                   Parameters   :: list({string(), string() | binary()}),
                   Headers      :: list({string(), string()})) ->
          #wm_reqdata{}.
make_get_wrq(Path, [], Headers) ->
    wrq:create('GET', http, {1,1}, Path, mochiweb_headers:from_list(Headers));
make_get_wrq(Path, Parameters, Headers) ->
    wrq:create('GET', http, {1,1}, Path ++ "?" ++ 
                   mochiweb_util:urlencode(Parameters),
               mochiweb_headers:from_list(Headers)).

%% @todo Make make_post_wrq work.
%% Using the function below produces the following error:
%%
%% **in function webmachine_request:new/1 (src/webmachine_request.erl, line 107)
%%   called as new(defined_on_call)
%% in call from wrq:req_body/1 (src/wrq.erl, line 113)
%% in call from oauth2_wrq:parse_body/1 (src/oauth2_wrq.erl, line 25)
%% ...
%% **error:function_clause
%%
%% Any help on how to create POST requests for unit testing will be appreciated.
-spec make_post_wrq(Path        :: string(),
                    Parameters  :: list({string(), string() | binary()}),
                    Headers     :: list({string(), string()})) ->
          #wm_reqdata{}.
make_post_wrq(Path, [], Headers) ->
    Request = wrq:create('POST', http, {1,1}, Path, 
                          mochiweb_headers:from_list(Headers)),
    wrq:set_req_body(<<"foo">>, Request);
make_post_wrq(Path, Parameters, Headers) ->
    Request = wrq:create('POST', http, {1,1}, Path,
                          mochiweb_headers:from_list(Headers)),
    wrq:set_req_body(<<"foo">>, Request).
