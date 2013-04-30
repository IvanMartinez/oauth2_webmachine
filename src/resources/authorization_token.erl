%% @author https://github.com/IvanMartinez
%% @copyright YYYY author.
%% @doc Example webmachine_resource.

-module(authorization_token).
-export([init/1, resource_exists/2]).

-include_lib("webmachine/include/webmachine.hrl").

init([]) -> {ok, undefined}.

resource_exists(ReqData, State) ->
    {false, ReqData, State}.
