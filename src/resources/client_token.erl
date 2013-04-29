%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(client_token).
-export([init/1, resource_exists/2]).

-include_lib("webmachine/include/webmachine.hrl").

init([]) -> {ok, undefined}.

resource_exists(ReqData, State) ->
    {false, ReqData, State}.
