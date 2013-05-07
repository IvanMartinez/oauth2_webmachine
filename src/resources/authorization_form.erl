%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Example webmachine_resource.

-module(authorization_form).
-export([init/1, allowed_methods/2, content_types_provided/2, process_get/2, process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").
-include("../include/oauth2_request.hrl").

init([]) -> {ok, undefined}.

allowed_methods(ReqData, State) ->
    {['GET', 'POST'], ReqData, State}.

content_types_provided(ReqData, State) ->
    {[{"text/html", process_get}], ReqData, State}.

process_get(ReqData, State) ->
    {HttpStatus, Body, Location} = process(wrq:req_qs(ReqData)),
    {{halt, HttpStatus}, wrq:set_resp_body(Body, ReqData), State}.

process_post(ReqData, State) ->
    error_logger:info_msg("process_post~n", []),
    {HttpStatus, Body, Location} = process(oauth2_wrq:parse_body(ReqData)),
    {{halt, HttpStatus}, wrq:set_resp_body(Body, ReqData), State}.

-spec process(Params :: list(string())) ->
    {non_neg_integer(), binary(), binary()}.
process(Params) ->
error_logger:info_msg("Params ~p~n", [Params]),
    case oauth2_wrq:get_request_id(Params) of
        undefined ->
            {400, html:bad_request(), <<>>};
        RequestId ->
error_logger:info_msg("request_id ~p~n", [RequestId]),
            case oauth2_wrq:get_owner_credentials(Params) of
                undefined ->
                    {400, html:bad_request(), <<>>};
                {Username, Password} ->
error_logger:info_msg("username ~p~n", [Username]),
error_logger:info_msg("password ~p~n", [Password]),
                    case oauth2_ets_backend:authenticate_username_password(Username, Password) of
                        {ok, OwnerIdentity} ->
                            case oauth2_ets_backend:retrieve_request(RequestId) of
                                {ok, #oauth2_request{client_id = ClientId, redirect_uri = undefined, scope = Scope, state = State}} ->
error_logger:info_msg("ClientId ~p~n", [ClientId]),
error_logger:info_msg("Scope ~p~n", [Scope]),
error_logger:info_msg("State ~p~n", [State]);
                                {ok, #oauth2_request{client_id = ClientId, redirect_uri = RedirectUri, scope = Scope, state = State}} ->
error_logger:info_msg("ClientId ~p~n", [ClientId]),
error_logger:info_msg("RedirectUri ~p~n", [RedirectUri]),
error_logger:info_msg("Scope ~p~n", [Scope]),
error_logger:info_msg("State ~p~n", [State]);
                                {error, _} ->
                                    {408, html:request_timeout(), <<>>}
                            end;
                        {error, _} ->
                            {401, html:unauthorized(), <<>>}
                    end
                    
            end
    end.
