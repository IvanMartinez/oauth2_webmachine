%% @author https://github.com/IvanMartinez
%% @copyright 2013-2014 author.
%% @doc Implements RFC6749 4.1. Authorization Code Grant, Authorization Request.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(authorization_code).

-export([init/1,
         allowed_methods/2, 
         malformed_request/2,
         to_html/2, 
         process_post/2]).

-include_lib("webmachine/include/webmachine.hrl").

-record(request, {response_type :: atom(),
                  client_id     :: binary(),
                  redirect_uri  :: binary(),
                  scope         :: binary() | oauth2:scope() | undefined,
                  state         :: binary() | undefined,
                  owner_credentials = {undefined, undefined}
                                :: {binary() | undefined,
                                    binary() | undefined}
                 }).

%% ====================================================================
%% API functions
%% ====================================================================

init([]) -> {ok, undefined}.

allowed_methods(ReqData, Context) ->
    {['GET', 'POST', 'HEAD'], ReqData, Context}.

malformed_request(ReqData, Context) ->
    WrqMethod = wrq:method(ReqData),
    case WrqMethod of
        'GET' ->
            Params = wrq:req_qs(ReqData);
        'POST' ->
            Params = oauth2_wrq:parse_body(ReqData)
    end,
    ResponseType = oauth2_wrq:get_response_type(Params),
    ClientId = oauth2_wrq:get_client_id(Params),
    Uri = oauth2_wrq:get_redirect_uri(Params),
    State = oauth2_wrq:get_state(Params),
    OwnerCredentials = oauth2_wrq:get_owner_credentials(Params), 
    if
        ResponseType == undefined ->
            {true, ReqData, Context};
        ClientId == undefined ->
            {true, ReqData, Context};
        Uri == undefined ->
            %% @todo 4.1.1 of the spec says the redirection URI is optional, 
            %% but it's not clear about what to do when it is missing and it
            %% is messy to implement with the current API of kivra/ouauth2.
            {true, ReqData, Context};
        (WrqMethod == 'POST') and (OwnerCredentials == undefined) ->
            {true, ReqData, Context};
        (WrqMethod == 'GET') ->
            Scope = oauth2_wrq:get_scope_binary(Params),
            {false, ReqData, [{request, #request{client_id = ClientId,
                                                 redirect_uri = Uri,
                                                 scope = Scope,
                                                 state = State}} |
                                Context]};
        true ->
            Scope = oauth2_wrq:get_scope(Params),
            {false, ReqData, [{request, #request{response_type = ResponseType,
                                                 client_id = ClientId,
                                                 redirect_uri = Uri,
                                                 scope = Scope,
                                                 state = State,
                                                 owner_credentials = 
                                                     OwnerCredentials}} |
                                Context]}
    end.

-spec to_html(ReqData   :: #wm_reqdata{},
              Context   :: term()) ->
        {{halt, pos_integer()}, #wm_reqdata{}, _}.
to_html(ReqData, Context) ->
    #request{response_type = ResponseType,
             client_id = ClientId,
             redirect_uri = RedirectURI,
             scope = Scope,
             state = State} = proplists:get_value(request, Context),
    BinaryResponseType = atom_to_binary(ResponseType, utf8),
    oauth2_wrq:html_response(
      ReqData, 
      200,
      << <<"<html><body>Application ">>/binary, ClientId/binary,
         <<" wants to access scope ">>/binary, Scope/binary,
         <<"<br><form action=\"authorization_code\" method=\"post\">"
           "User: <input type=\"text\" name=\"username\"><br>"
           "Password: <input type=\"password\" name=\"password\"><br>"
           "<input type=\"hidden\" name=\"response_type\" value=\"">>/binary,
           BinaryResponseType/binary, <<"\"><br>"
           "<input type=\"hidden\" name=\"client_id\" value=\"">>/binary,
           ClientId/binary, <<"\"><br>"
           "<input type=\"hidden\" name=\"redirect_uri\" value=\"">>/binary,
           RedirectURI/binary, <<"\"><br>"
           "<input type=\"hidden\" name=\"scope\" value=\"">>/binary,
           Scope/binary, <<"\"><br>"
           "<input type=\"hidden\" name=\"state\" value=\"">>/binary,
           State/binary, <<"\"><br>"
           "<input type=\"submit\" value=\"Accept\">"
           "</form></body></html>">>/binary >>,
      Context).

-spec process_post(ReqData   :: #wm_reqdata{},
                   Context   :: term()) ->
        {{halt, pos_integer()}, #wm_reqdata{}, _}.
process_post(ReqData, Context) ->
    #request{response_type = ResponseType,
             client_id = ClientId,
             redirect_uri = RedirectURI,
             scope = Scope,
             state = State,
             owner_credentials = OwnerCredentials} = 
        proplists:get_value(request, Context),
    case ResponseType of
        code ->
            case oauth2:authorize_code_request(OwnerCredentials,
                                               ClientId,
                                               RedirectURI,
                                               Scope, none) of
                {ok, {_AppContext, Authorization}} ->
                    {ok, {_AppContext2, Response}} = 
                        oauth2:issue_code(Authorization, none),
                    {ok, Code} = oauth2_response:access_code(Response),
                    oauth2_wrq:redirected_authorization_code_response(
                        ReqData, RedirectURI, Code, State, Context);
                {error, unauthorized_client} ->
                    %% cliend_id is not registered or redirection_uri is not 
                    %% valid
                    oauth2_wrq:json_error_response(ReqData, unauthorized_client, 
                                                   Context);
                {error, Error} ->
                    oauth2_wrq:redirected_error_response(
                        ReqData, RedirectURI, Error, State, Context)
            end;
        _ ->
            oauth2_wrq:redirected_error_response(
                ReqData, RedirectURI, unsupported_response_type, State, 
                Context)
   end.
