%% @author https://github.com/IvanMartinez
%% @copyright 2013 author.
%% @doc Help functions for tests.
%% Distributed under the terms and conditions of the Apache 2.0 license.

-module(test_util).

-include_lib("webmachine/include/wm_reqdata.hrl").

%% ====================================================================
%% API functions
%% ====================================================================

-export([request/3,
         request/4,
         result_body/1,
         result_location/1,
         result_status/1,
         simple_json_to_proplist/1,
         split_url/1]).

-spec request(URL           :: httpc:url(),
              Method        :: http:method(),
              Parameters    :: proplists:proplist()) -> term().
request(URL, Method, Parameters) ->
    request(URL, Method, [], Parameters).

-spec request(URL           :: httpc:url(),
              Method        :: http:method(),
              Headers       :: proplists:proplist(),
              Parameters    :: proplists:proplist()) -> term().
request(URL, Method, Headers, Parameters) ->
    ParametersString = proplist_to_query_string(Parameters),
    case Method of
        get ->
            {ok, Result} = httpc:request(Method, 
                                         {URL ++ "?" ++ ParametersString, 
                                          Headers},
                                         [], []);
        post ->
            {ok, Result} = httpc:request(Method, 
                                         {URL, 
                                          Headers, 
                                          "application/x-www-form-urlencoded",
                                          ParametersString},
                                         [], [])
    end,
    Result.

-spec result_body({httpc:status_line(), httpc:headers(), string()}) -> 
          string().
result_body({_, _, Body}) ->
    Body.

-spec result_location({httpc:status_line(), httpc:headers(), string()}) -> 
          string().
result_location({_, Headers, _}) ->
    case proplists:get_value("location", Headers) of
        undefined -> "";
        Location -> Location
    end.

-spec result_status({httpc:status_line(), httpc:headers(), string()}) -> 
          integer().
result_status({{_, Code, _}, _, _}) ->
    Code.

-spec simple_json_to_proplist(JsonString    :: string()) -> 
          proplists:proplist().
simple_json_to_proplist(JsonString) ->
    % Remove the following characters: { } "
    AttributeValueString = re:replace(JsonString, "\{|\}|\"", "", 
                                    [global, {return,list}]),
    lists:filtermap(fun(AttributeValue) ->
                            case string:tokens(AttributeValue, ":") of
                                [Attribute, Value] ->
                                    {true, {Attribute, Value}};
                                _ ->
                                    false
                            end
                    end,
                    string:tokens(AttributeValueString, ",")).

-spec split_url(URL :: string()) -> {string(), proplists:proplist()}.
split_url(URL) ->
    case string:tokens(URL, "?") of
        [] -> {"", 0, []};
        [BaseURL] -> {BaseURL, 0, []};
        [BaseURL, QueryString] ->
            QueryProplist = 
                lists:filtermap(fun(NameValue) ->
                                        case string:tokens(NameValue, "=") of
                                            [Name, Value] ->
                                                {true, {Name, Value}};
                                            _ ->
                                                false
                                        end
                                end,
                                string:tokens(QueryString, "&")),
            {BaseURL, QueryProplist}
    end.

%% ====================================================================
%% Internal functions
%% ====================================================================

-spec proplist_to_query_string(Proplist :: proplists:proplist()) -> string().
proplist_to_query_string([]) ->
    "";
proplist_to_query_string([{Parameter, Value}]) ->
    Parameter ++ "=" ++ Value; 
proplist_to_query_string([{Parameter, Value} | Remaining]) ->
    Parameter ++ "=" ++ Value ++ "&" ++ proplist_to_query_string(Remaining).
