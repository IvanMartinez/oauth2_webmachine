%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Example webmachine_resource.

-module(owner_token_resource).
-export([init/1, allowed_methods/2, content_types_provided/2, process_post/2, process/2]).

-include_lib("webmachine/include/webmachine.hrl").

init([]) -> {ok, undefined}.

allowed_methods(ReqData, State) ->
    {['POST', 'GET'], ReqData, State}.

content_types_provided(ReqData, State) ->
    {[{"application/json;charset=UTF-8", process}], ReqData, State}.

process_post(ReqData, State) ->
    process(ReqData, State).

process(ReqData, State) ->
    ParsedBody = oauth2_wrq:parse_body(ReqData),
    case oauth2_wrq:get_grant_type(ParsedBody) of
        password ->
            case oauth2_wrq:get_owner_credentials(ParsedBody) of
                undefined ->
                    oauth2_wrq:invalid_request_response(ReqData, State);
                {Username, Password} ->
                    case oauth2:authorize_password(Username, Password, oauth2_wrq:get_scope(ParsedBody)) of
                        {ok, _Identity, Response} ->
                            {ok, Token} = oauth2_response:access_token(Response),
                            Type = <<"bearer">>,    %% There is no oauth2_response function to extract the type from a response
                            {ok, Expires} = oauth2_response:expires_in(Response),
                            {ok, Scope} = oauth2_response:scope(Response),
                            oauth2_wrq:access_token_response(ReqData, binary_to_list(Token), binary_to_list(Type), Expires, Scope, State);
                        {error, invalid_scope} ->
                            oauth2_wrq:invalid_scope_response(ReqData, State);
                        {error, _Reason} ->
                            oauth2_wrq:invalid_grant_response(ReqData, State)
                    end
            end;
        undefined ->
            oauth2_wrq:invalid_request_response(ReqData, State);
        _ ->
            oauth2_wrq:unsupported_grant_type_response(ReqData, State)
    end.
