%% @author https://github.com/IvanMartinez
%% @doc @todo Add description to oauth2_wrq.

-module(oauth2_wrq).

-include_lib("webmachine/include/wm_reqdata.hrl").

-define(AUTHENTICATE_REALM, "oauth2_webmachine").
-type(wm_reqdata() :: #wm_reqdata{}).

%% ====================================================================
%% API functions
%% ====================================================================

-export([parse_body/1, get_grant_type/1, get_response_type/1, 
         get_owner_credentials/1, get_client_id/1, get_client_credentials/2, 
         get_redirect_uri/1, get_scope/1, get_state/1, get_request_id/1]).
-export([access_token_response/6, json_error_response/3, html_response/4,
         redirected_error_response/5]).

-spec parse_body(Request :: wm_reqdata()) ->
          list(string()).
parse_body(Request) ->
%% error_logger:info_msg("parse_body Request = ~p~n", [Request]),    
%% error_logger:info_msg("parse_body Body = ~p~n", [wrq:req_body(Request)]),    
    case wrq:req_body(Request) of
        undefined ->
            [];
        <<>> ->
            [];
        Body ->
            mochiweb_util:parse_qs(Body)
    end.

-spec get_client_id(Params :: list(string())) ->
          binary() | undefined.
get_client_id([]) ->
    undefined;
get_client_id(Params) ->
    case lists:keyfind("client_id", 1, Params) of
        {"client_id", Id} ->
            list_to_binary(Id);
        false ->
            undefined
    end.

-spec get_client_credentials(Params :: list(string()), 
                             Request :: wm_reqdata()) ->
          {binary(), binary()} | undefined.
get_client_credentials(Params, #wm_reqdata{} = Request) ->
    case wrq:get_req_header("Authorization", Request) of
        "Basic " ++ B64String ->
            b64_credentials(B64String);
        undefined ->
            case lists:keyfind("client_id", 1, Params) of
                {"client_id", Id} ->
                    case lists:keyfind("client_secret", 1, Params) of
                        {"client_secret", Secret} ->
                            {list_to_binary(Id), list_to_binary(Secret)};
                        false ->
                            undefined
                        end;
                false ->
                    undefined
            end;
        _ ->
            undefined
    end.

-spec get_grant_type(Params :: list(string())) ->
          authorization_code | client_credentials | password | undefined | 
              unsupported.
get_grant_type([]) ->
    undefined;
get_grant_type(Params) ->
    case lists:keyfind("grant_type", 1, Params) of
        {"grant_type", "authorization_code"} ->
            authorization_code;
        {"grant_type", "client_credentials"} ->
            client_credentials;
        {"grant_type", "password"} ->
            password;
        {"grant_type", _} ->
            unsupported;
        false ->
            undefined
    end.

-spec get_response_type(Params :: list(string())) ->
          code | undefined | unsupported.
get_response_type([]) ->
    undefined;
get_response_type(Params) ->
    case lists:keyfind("response_type", 1, Params) of
        {"response_type", "code"} ->
            code;
        {"response_type", _} ->
            unsupported;
        false ->
            undefined
    end.

-spec get_owner_credentials(Params :: list(string())) ->
          {binary(), binary()} | undefined.
get_owner_credentials(Params) ->
    case lists:keyfind("username", 1, Params) of
        {"username", Name} ->
            case lists:keyfind("password", 1, Params) of
                {"password", Password} ->
                    {list_to_binary(Name), list_to_binary(Password)};
                false ->
                    undefined
                end;
        false ->
            undefined
    end.

-spec get_redirect_uri(Params :: list(string())) ->
          binary() | undefined.
get_redirect_uri([]) ->
    undefined;
get_redirect_uri(Params) ->
    case lists:keyfind("redirect_uri", 1, Params) of
        {"redirect_uri", Uri} ->
            list_to_binary(Uri);
        false ->
            undefined
    end.

-spec get_scope(Params :: list(string())) ->
          [binary()] | [] | undefined.
get_scope([]) ->
    undefined;
get_scope(Params) ->
    case lists:keyfind("scope", 1, Params) of
        {"scope", ""} ->
            [];
        {"scope", ScopeString} ->
            [list_to_binary(X) || X <- string:tokens(ScopeString, " ")];
        false ->
            undefined
    end.

-spec get_state(Params :: list(string())) ->
          binary() | undefined.
get_state([]) ->
    undefined;
get_state(Params) ->
    case lists:keyfind("state", 1, Params) of
        {"state", State} ->
            list_to_binary(State);
        false ->
            undefined
    end.

-spec get_request_id(Params :: list(string())) ->
          binary() | undefined.
get_request_id([]) ->
    undefined;
get_request_id(Params) ->
    case lists:keyfind("request_id", 1, Params) of
        {"request_id", Id} ->
            list_to_binary(Id);
        false ->
            undefined
    end.

-spec access_token_response(Request     :: wm_reqdata(),
                            Token       :: string(),
                            Type        :: string(),
                            Expires     :: non_neg_integer(),
                            Scope       :: [] | [string()],
                            State       :: term()) ->
    {{halt, 200}, wm_reqdata(), term()}.
access_token_response(#wm_reqdata{} = Request, Token, Type, Expires, Scope, 
                      State) ->
    {{halt, 200}, wrq:set_resp_body("{\"access_token\":\"" ++ Token ++ 
                                        "\",\"token_type\":\"" ++ Type ++ 
                                        "\",\"expires_in\":" ++ 
                                        integer_to_list(Expires) ++ 
                                        ",\"scope\":\"" ++ 
                                        scope_string(Scope) ++"\"}", Request), 
     State}.

-spec json_error_response(Request   :: #wm_reqdata{},
                          Error     :: invalid_client | invalid_grant | 
                              invalid_request | invalid_scope | 
                              unsupported_grant_type | 
                              unsupported_response_type,
                          Context   :: term()) ->
          {{halt, 400 | 401}, #wm_reqdata{}, term()}.
json_error_response(Request, Error, Context) ->
    case Error of
        invalid_client ->
            Response = wrq:set_resp_header("WWW-Authenticate", 
                                           "Basic realm=\"" ++ 
                                               ?AUTHENTICATE_REALM ++ "\"", 
                                           Request),
            {{halt, 401}, wrq:set_resp_body("{\"error\":\"invalid_client\"}", 
                                            Response), Context};
        invalid_grant ->
            {{halt, 400}, wrq:set_resp_body("{\"error\":\"invalid_grant\"}",
                                            Request), Context};
        invalid_request ->
            {{halt, 400}, wrq:set_resp_body("{\"error\":\"invalid_request\"}", 
                                            Request), Context};
        invalid_scope ->
            {{halt, 400}, wrq:set_resp_body("{\"error\":\"invalid_scope\"}", 
                                            Request), Context};
        unsupported_grant_type ->
            {{halt, 400}, wrq:set_resp_body(
               "{\"error\":\"unsupported_grant_type\"}", Request), Context}
    end.

-spec html_response(ReqData     :: wm_reqdata(),
                    HttpStatus  :: pos_integer(),
                    Body        :: binary(),
                    Context     :: term()) ->
          {{halt, pos_integer()}, wm_reqdata(), term()}.
html_response(ReqData, HttpStatus, Body, Context) ->
    {{halt, HttpStatus}, wrq:set_resp_body(Body, ReqData), Context}.

-spec redirected_error_response(Request :: wm_reqdata(),
                                Uri     :: binary(),
                                Error   :: access_denied | invalid_request | 
                                    request_timeout | server_error | 
                                    unsupported_response_type,
                                State   :: binary(),
                                Context :: term()) ->
          {{halt, 302}, wm_reqdata(), term()}.
redirected_error_response(Request, Uri, Error, State, Context) ->
    ErrorString = case Error of
                      access_denied ->
                          "access_denied";
                      invalid_request ->
                          "invalid_request";
                      request_timeout ->
                          "request_timeout";
                      server_error ->
                          "server_error";
                      unsupported_response_type ->
                          "unsupported_response_type"
                  end,
    {{halt, 302}, wrq:set_resp_header("Location", binary_to_list(Uri) ++
                                          "?error=" ++ ErrorString ++
                                          state_to_uri(State), Request),
     Context}.

%% -spec redirection_uri(Uri           :: binary(),
%%                       Parameters    :: list({string(), 
%%                                              string() | binary()})) ->
%%           binary().
%% redirection_uri(Uri, Parameters) ->
%%     <<Uri/binary, $?, mochiweb_util:urlencode(Parameters) >>.

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

-spec scope_string(Scope :: [binary()]) ->
          string().
scope_string([]) ->
    "";
scope_string([ScopeItem]) ->
    binary_to_list(ScopeItem);
scope_string([ScopeItem | RestOfScope]) ->
    binary_to_list(ScopeItem) ++ " " ++ scope_string(RestOfScope).

-spec state_to_uri(State :: string() | undefined) ->
          string().
state_to_uri(undefined) ->
    "";
state_to_uri(<<>>) ->
    "";
state_to_uri(State) ->
    "&state=" ++ binary_to_list(State).
