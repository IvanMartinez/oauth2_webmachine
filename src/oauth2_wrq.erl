%% @author https://github.com/IvanMartinez
%% @doc @todo Add description to oauth2_wrq.

-module(oauth2_wrq).

-include("../include/oauth2_wrq.hrl").

%% ====================================================================
%% API functions
%% ====================================================================

-export([parse_body/1, get_grant_type/1, get_response_type/1, get_owner_credentials/1, get_client_id/1, get_client_credentials/2, get_scope/1]).
-export([access_token_response/6, invalid_client_response/2, invalid_grant_response/2, invalid_request_response/2, 
         invalid_scope_response/2, unsupported_grant_type_response/2, unsupported_response_type_response/2]).

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

-spec get_client_id(ParsedBody :: list(string())) ->
          binary() | undefined.
get_client_id([]) ->
    undefined;
get_client_id(Id) ->
    case lists:keyfind("client_id", 1, Id) of
        {"client_id", Id} ->
            list_to_binary(Id);
        false ->
            undefined
    end.

-spec get_client_credentials(ParsedBody :: list(string()), Request :: wm_reqdata()) ->
          {binary(), binary()} | undefined.
get_client_credentials(ParsedBody, #wm_reqdata{} = Request) ->
    case wrq:get_req_header("Authorization", Request) of
        "Basic " ++ B64String ->
            b64_credentials(B64String);
        undefined ->
            case lists:keyfind("client_id", 1, ParsedBody) of
                {"client_id", Id} ->
                    case lists:keyfind("client_secret", 1, ParsedBody) of
                        {"client_secret", Secret} ->
                            {list_to_binary(Id), list_to_binary(Secret)};
                        false ->
                            undefined
                        end;
                false ->
                    undefined
            end
    end.

-spec get_grant_type(ParsedBody :: list(string())) ->
          authorization_code | client_credentials | password | undefined | unsupported.
get_grant_type([]) ->
    undefined;
get_grant_type(ParsedBody) ->
    case lists:keyfind("grant_type", 1, ParsedBody) of
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

-spec get_response_type(ParsedBody :: list(string())) ->
          code | undefined | unsupported.
get_response_type([]) ->
    undefined;
get_response_type(ParsedBody) ->
    case lists:keyfind("response_type", 1, ParsedBody) of
        {"response_type", "code"} ->
            code;
        {"grant_type", _} ->
            unsupported;
        false ->
            undefined
    end.

-spec get_owner_credentials(ParsedBody :: list(string())) ->
          {binary(), binary()} | undefined.
get_owner_credentials(ParsedBody) ->
    case lists:keyfind("username", 1, ParsedBody) of
        {"username", Name} ->
            case lists:keyfind("password", 1, ParsedBody) of
                {"password", Password} ->
                    {list_to_binary(Name), list_to_binary(Password)};
                false ->
                    undefined
                end;
        false ->
            undefined
    end.

-spec get_scope(ParsedBody :: list(string())) ->
          [binary()] | [] | undefined.
get_scope([]) ->
    undefined;
get_scope(ParsedBody) ->
    case lists:keyfind("scope", 1, ParsedBody) of
        {"scope", ""} ->
            [];
        {"scope", ScopeString} ->
            [list_to_binary(X) || X <- string:tokens(ScopeString, " ")];
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
access_token_response(#wm_reqdata{} = Request, Token, Type, Expires, Scope, State) ->
    {{halt, 200}, wrq:set_resp_body("{\"access_token\":\"" ++ Token ++ 
                                        "\",\"token_type\":\"" ++ Type ++ 
                                        "\",\"expires_in\":" ++ integer_to_list(Expires) ++ 
                                        ",\"scope\":\"" ++ scope_string(Scope) ++"\"}", Request), State}.

-spec invalid_client_response(Request   :: wm_reqdata(),
                              State     :: term()) ->
          {{halt, 401}, wm_reqdata(), term()}.
invalid_client_response(#wm_reqdata{} = Request, State) ->
    Response = wrq:set_resp_header("WWW-Authenticate", "Basic realm=\"" ++ ?AUTHENTICATE_REALM ++ "\"", Request),
    {{halt, 401}, wrq:set_resp_body("{\"error\":\"invalid_client\"}", Response), State}.

-spec invalid_grant_response(Request    :: wm_reqdata(),
                             State      :: term()) ->
          {{halt, 400}, wm_reqdata(), term()}.
invalid_grant_response(#wm_reqdata{} = Request, State) ->
    {{halt, 400}, wrq:set_resp_body("{\"error\":\"invalid_grant\"}", Request), State}.

-spec invalid_request_response(Request  :: wm_reqdata(),
                               State    :: term()) ->
          {{halt, 400}, wm_reqdata(), term()}.
invalid_request_response(#wm_reqdata{} = Request, State) ->
    {{halt, 400}, wrq:set_resp_body("{\"error\":\"invalid_request\"}", Request), State}.

-spec invalid_scope_response(Request    :: wm_reqdata(),
                             State      :: term()) ->
    {{halt, 400}, wm_reqdata(), term()}.
invalid_scope_response(#wm_reqdata{} = Request, State) ->
    {{halt, 400}, wrq:set_resp_body("{\"error\":\"invalid_scope\"}", Request), State}.

-spec unsupported_grant_type_response(Request   :: wm_reqdata(),
                                      State     :: term()) ->
          {{halt, 400}, wm_reqdata(), term()}.
unsupported_grant_type_response(#wm_reqdata{} = Request, State) ->
    {{halt, 400}, wrq:set_resp_body("{\"error\":\"unsupported_grant_type\"}", Request), State}.

-spec unsupported_response_type_response(Request    :: wm_reqdata(),
                                         State      :: term()) ->
          {{halt, 400}, wm_reqdata(), term()}.
unsupported_response_type_response(#wm_reqdata{} = Request, State) ->
    {{halt, 400}, wrq:set_resp_body("{\"error\":\"unsupported_response_type\"}", Request), State}.

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

