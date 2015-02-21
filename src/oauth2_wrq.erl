%% @copyright 2013 author.
%% @doc Functions to read webmachine OAuth2 requests and generate responses.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(oauth2_wrq).

-include_lib("webmachine/include/wm_reqdata.hrl").

-define(AUTHENTICATE_REALM, "oauth2_webmachine").

%% ====================================================================
%% API functions
%% ====================================================================

-export([parse_body/1, get_client_credentials/2, get_client_id/1, get_code/1,
         get_grant_type/1, get_refresh_token/1, get_response_type/1, 
         get_owner_credentials/1, get_redirect_uri/1, get_scope/1,
         get_scope_binary/1, 
         get_state/1,
         get_request_id/1]).
-export([access_token_response/6, access_refresh_token_response/7,
         json_error_response/3, html_response/4,
         redirected_access_token_response/8,
         redirected_authorization_code_response/5,
         redirected_error_response/5]).

-spec parse_body(Request :: #wm_reqdata{}) ->
          list({term(), term()}).
parse_body(Request) ->
    case wrq:req_body(Request) of
        undefined ->
            [];
        <<>> ->
            [];
        Body ->
            mochiweb_util:parse_qs(Body)
    end.

-spec get_client_credentials(Params     :: proplists:proplist(), 
                             Request    :: #wm_reqdata{}) ->
          {binary(), binary()} | undefined.
get_client_credentials(Params, #wm_reqdata{} = Request) ->
    case wrq:get_req_header("Authorization", Request) of
        "Basic " ++ B64String ->
            b64_credentials(B64String);
        undefined ->
            case {proplists:get_value("client_id", Params),
                  proplists:get_value("client_secret", Params)} of
                {undefined, _} -> undefined;
                {_, undefined} -> undefined;
                {Id, Secret} ->
                    {list_to_binary(Id), list_to_binary(Secret)}
            end;
        _ ->
            undefined
    end.

-spec get_client_id(Params :: proplists:proplist()) ->
          binary() | undefined.
get_client_id(Params) ->
    case proplists:get_value("client_id", Params) of
        undefined ->
            undefined;
        Id ->
            list_to_binary(Id)
    end.

-spec get_code(Params :: proplists:proplist()) ->
          binary() | undefined.
get_code([]) ->
    undefined;
get_code(Params) ->
    case proplists:get_value("code", Params) of
        undefined ->
            undefined;
        Code ->
            list_to_binary(Code)
    end.

-spec get_grant_type(Params :: proplists:proplist()) ->
          authorization_code | client_credentials | password | refresh_token |
              undefined | unsupported.
get_grant_type([]) ->
    undefined;
get_grant_type(Params) ->
    case proplists:get_value("grant_type", Params) of
        undefined ->
            undefined;
        Code ->
            list_to_binary(Code)
    end.

-spec get_refresh_token(Params :: proplists:proplist()) ->
          binary() | undefined.
get_refresh_token([]) ->
    undefined;
get_refresh_token(Params) ->
    case proplists:get_value("refresh_token", Params) of
        undefined ->
            undefined;
        Token ->
            list_to_binary(Token)
    end.

-spec get_response_type(Params :: proplists:proplist()) ->
          code | token | undefined | unsupported.
get_response_type(Params) ->
    case proplists:get_value("response_type", Params) of
        undefined ->
            undefined;
        Code ->
            list_to_binary(Code)
    end.
        
-spec get_owner_credentials(Params :: proplists:proplist()) ->
          {binary(), binary()} | undefined.
get_owner_credentials(Params) ->
    case proplists:get_value("username", Params) of
        undefined ->
            undefined;
        Username ->
            case proplists:get_value("password", Params) of
                undefined ->
                    undefined;
                Password ->
                    {list_to_binary(Username), list_to_binary(Password)}
            end
    end.

-spec get_redirect_uri(Params :: proplists:proplist()) ->
          binary() | undefined.
get_redirect_uri(Params) ->
    case proplists:get_value("redirect_uri", Params) of
        undefined ->
            undefined;
        Uri ->
            list_to_binary(Uri)
    end.

-spec get_scope(Params :: proplists:proplist()) ->
          oauth2:scope() | undefined.
get_scope([]) ->
    undefined;
get_scope(Params) ->
    case proplists:get_value("scope", Params) of
        undefined ->
            undefined;
        "" ->
            [];
        ScopeString ->
            [list_to_binary(X) || X <- string:tokens(ScopeString, " ")]
    end.

-spec get_scope_binary(Params :: proplists:proplist()) ->
          binary() | undefined.
get_scope_binary([]) ->
    undefined;
get_scope_binary(Params) ->
    case proplists:get_value("scope", Params) of
        undefined ->
            undefined;
        ScopeString ->
            list_to_binary(ScopeString)
    end.

-spec get_state(Params :: proplists:proplist()) ->
          binary() | undefined.
get_state([]) ->
    undefined;
get_state(Params) ->
    case proplists:get_value("state", Params) of
        undefined ->
            undefined;
        State ->
            list_to_binary(State)
    end.

-spec get_request_id(Params :: proplists:proplist()) ->
          binary() | undefined.
get_request_id([]) ->
    undefined;
get_request_id(Params) ->
    case proplists:get_value("request_id", Params) of
        undefined ->
            undefined;
        Id ->
            list_to_binary(Id)
    end.

-spec access_token_response(Request     :: #wm_reqdata{},
                            AccessToken :: binary(),
                            Type        :: binary(),
                            Expires     :: non_neg_integer(),
                            Scope       :: list(binary()),
                            State       :: term()) ->
    {{halt, 200}, #wm_reqdata{}, term()}.
access_token_response(#wm_reqdata{} = Request, AccessToken, Type, Expires, 
                      Scope, State) ->
    Response = wrq:set_resp_headers([{"Cache-Control", "no-store"},
                                     {"Pragma", "no-cache"}],
                                    Request),
    {{halt, 200}, wrq:set_resp_body("{\"access_token\":\"" ++ 
                                        binary_to_list(AccessToken) ++ 
                                        "\",\"token_type\":\"" ++ 
                                        binary_to_list(Type) ++ 
                                        "\",\"expires_in\":" ++ 
                                        integer_to_list(Expires) ++ 
                                        ",\"scope\":\"" ++ 
                                        scope_string(Scope) ++"\"}", Response), 
     State}.

-spec access_refresh_token_response(Request         :: #wm_reqdata{},
                                    AccessToken     :: binary(),
                                    Type            :: binary(),
                                    Expires         :: non_neg_integer(),
                                    RefreshToken    :: binary(),
                                    Scope           :: list(binary()),
                                    State           :: term()) ->
    {{halt, 200}, #wm_reqdata{}, term()}.
access_refresh_token_response(#wm_reqdata{} = Request, AccessToken, Type, 
                              Expires, RefreshToken, Scope, State) ->
    Response = wrq:set_resp_headers([{"Cache-Control", "no-store"},
                                     {"Pragma", "no-cache"}],
                                    Request),
    {{halt, 200}, wrq:set_resp_body("{\"access_token\":\"" ++ 
                                        binary_to_list(AccessToken) ++ 
                                        "\",\"token_type\":\"" ++ 
                                        binary_to_list(Type) ++ 
                                        "\",\"expires_in\":" ++ 
                                        integer_to_list(Expires) ++ 
                                        ",\"refresh_token\":\"" ++ 
                                        binary_to_list(RefreshToken) ++
                                        "\",\"scope\":\"" ++
                                        scope_string(Scope) ++"\"}", Response), 
     State}.


-spec json_error_response(Request   :: #wm_reqdata{},
                          Error     :: invalid_client | invalid_grant | 
                              invalid_request | invalid_scope |
                              unauthorized_client | unsupported_grant_type | 
                              unsupported_response_type,
                          Context   :: term()) ->
          {{halt, 400 | 403}, #wm_reqdata{}, term()}.
json_error_response(Request, Error, Context) ->
    JSONResponse = wrq:set_resp_header("Content-Type", "application/json",
                                       Request),
    case Error of
        invalid_client ->
            Response = wrq:set_resp_header("WWW-Authenticate", "Basic", 
                                           JSONResponse),
            {{halt, 401}, wrq:set_resp_body("{\"error\":\"invalid_client\"}", 
                                            Response), Context};
        unauthorized_client ->
            {{halt, 403}, wrq:set_resp_body(
               "{\"error\":\"unauthorized_client\"}", JSONResponse), Context};
        Other ->
            {{halt, 400}, wrq:set_resp_body(
               lists:flatten(io_lib:format("{\"error\":\"~p\"}", [Other])),
               JSONResponse), Context}
    end.

-spec html_response(ReqData     :: #wm_reqdata{},
                    HttpStatus  :: pos_integer(),
                    Body        :: binary(),
                    Context     :: term()) ->
          {{halt, pos_integer()}, #wm_reqdata{}, term()}.
html_response(ReqData, HttpStatus, Body, Context) ->
    {{halt, HttpStatus}, wrq:set_resp_body(Body, ReqData), Context}.

-spec redirected_access_token_response(Request  :: #wm_reqdata{},
                                       Uri      :: binary(),
                                       Token    :: binary(),
                                       Type     :: binary(),
                                       Expires  :: non_neg_integer(),
                                       Scope    :: [binary()],
                                       State    :: binary(),
                                       Context  :: term()) ->
          {{halt, 302}, #wm_reqdata{}, term()}.
redirected_access_token_response(Request, Uri, Token, Type, Expires, Scope,
                                 State, Context) ->
    {{halt, 302}, wrq:set_resp_header(
       "Location", binary_to_list(Uri) ++ "?access_token=" ++ 
           binary_to_list(Token) ++ "&token_type=" ++ binary_to_list(Type) ++
           "&expires_in=" ++ integer_to_list(Expires) ++ "&scope=" ++ 
            scope_string(Scope) ++ state_to_uri(State),
       Request),
     Context}.

-spec redirected_authorization_code_response(Request    :: #wm_reqdata{},
                                             Uri        :: binary(),
                                             Code       :: binary(),
                                             State      :: binary(),
                                             Context    :: term()) ->
          {{halt, 302}, #wm_reqdata{}, term()}.
redirected_authorization_code_response(Request, Uri, Code, State, Context) ->
    {{halt, 302}, wrq:set_resp_header("Location", binary_to_list(Uri) ++
                                          "?code=" ++ binary_to_list(Code) ++
                                          state_to_uri(State), Request),
     Context}.

-spec redirected_error_response(Request :: #wm_reqdata{},
                                Uri     :: binary(),
                                Error   :: access_denied | invalid_request |
                                    invalid_scope | request_timeout | 
                                    server_error | unauthorized_client |
                                    unsupported_grant_type |
                                    unsupported_response_type,
                                State   :: binary(),
                                Context :: term()) ->
          {{halt, 302}, #wm_reqdata{}, term()}.
redirected_error_response(Request, Uri, Error, State, Context) ->
    ErrorString = case Error of
                      access_denied ->
                          "access_denied";
                      invalid_request ->
                          "invalid_request";
                      invalid_scope ->
                          "invalid_scope";
                      request_timeout ->
                          "request_timeout";
                      server_error ->
                          "server_error";
                      unauthorized_client ->
                          "unauthorized_client";
                      unsupported_grant_type ->
                          "unsupported_grant_type";
                      unsupported_response_type ->
                          "unsupported_response_type"
                  end,
    {{halt, 302}, wrq:set_resp_header("Location", binary_to_list(Uri) ++
                                          "?error=" ++ ErrorString ++
                                          state_to_uri(State), Request),
     Context}.

%% ====================================================================
%% Internal functions
%% ====================================================================

-spec b64_credentials(B64String :: string()) ->
          {binary(), binary()} | undefined.
b64_credentials(B64String) ->
    String = base64:mime_decode_to_string(B64String),
    case string:tokens(String, ":") of
        [Id, Secret] -> {list_to_binary(Id), list_to_binary(Secret)};
        _ -> undefined
    end.

-spec scope_string(Scope :: list(binary())) ->
          string().
scope_string([]) ->
    "";
scope_string([ScopeItem]) ->
    binary_to_list(ScopeItem);
scope_string([ScopeItem | RestOfScope]) ->
    binary_to_list(ScopeItem) ++ " " ++ scope_string(RestOfScope).

-spec state_to_uri(State :: binary() | undefined) ->
          string().
state_to_uri(undefined) ->
    "";
state_to_uri(<<>>) ->
    "";
state_to_uri(State) ->
    "&state=" ++ binary_to_list(State).
