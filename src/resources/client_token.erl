%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Example webmachine_resource.

-module(client_token).
-export([init/1, allowed_methods/2, content_types_provided/2, process_get/2, 
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

init([]) -> {ok, undefined}.

allowed_methods(ReqData, State) ->
    {['GET', 'POST'], ReqData, State}.

content_types_provided(ReqData, State) ->
    {[{"application/json;charset=UTF-8", process_get}], ReqData, State}.

process_get(ReqData, State) ->
    process(ReqData, wrq:req_qs(ReqData), State).

process_post(ReqData, State) ->
    process(ReqData, oauth2_wrq:parse_body(ReqData), State).

process(ReqData, Params, State) ->
    case oauth2_wrq:get_grant_type(Params) of
        client_credentials ->
            case oauth2_wrq:get_client_credentials(Params, ReqData) of
                undefined ->
                    oauth2_wrq:invalid_client_response(ReqData, State);
                {ClientId, ClientSecret} ->
                    case oauth2:authorize_client_credentials(ClientId, 
                                                ClientSecret, 
                                                oauth2_wrq:get_scope(Params)) of
                        {ok, _Identity, Response} ->
                            {ok, Token} = 
                                oauth2_response:access_token(Response),
                            %% There is no oauth2_response function to extract
                            %% the type from a response
                            Type = <<"bearer">>,
                            {ok, Expires} = 
                                oauth2_response:expires_in(Response),
                            {ok, Scope} = oauth2_response:scope(Response),
                            oauth2_wrq:access_token_response(ReqData, 
                                                          binary_to_list(Token),
                                                          binary_to_list(Type),
                                                          Expires, Scope,
                                                          State);
                        {error, invalid_scope} ->
                            oauth2_wrq:invalid_scope_response(ReqData, State);
                        {error, _Reason} ->
                            oauth2_wrq:invalid_client_response(ReqData, State)
                    end
            end;
        undefined ->
            oauth2_wrq:invalid_request_response(ReqData, State);
        _ ->
            oauth2_wrq:unsupported_grant_type_response(ReqData, State)
    end.
