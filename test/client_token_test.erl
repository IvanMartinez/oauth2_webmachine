%% @author https://github.com/IvanMartinez
%% @doc Tests for client_token resource.

-module(client_token_test).

-include_lib("eunit/include/eunit.hrl").

-define(CLIENT_TOKEN_URL, "http://127.0.0.1:8000/client_token").
-define(CLIENT1_ID, "ConfidentialClient").
-define(CLIENT1_SECRET, "Secret1").
-define(CLIENT1_URI, "http://cclient.uri").
-define(CLIENT1_SCOPE, "root.a.1 root.x.y").
-define(CLIENT1_SCOPE2, "root.a.2").
-define(BASIC_CREDENTIALS(ID, SECRET), "Basic " ++ 
            base64:encode_to_string(ID ++ ":" ++ SECRET)).

%% ===================================================================
%% Setup functions
%% ===================================================================

setup_test_() ->
    {setup, 
        fun before_tests/0,
        fun after_tests/1,
        fun (Context) -> [bad_request_tests(Context),
                          unauthorized_tests(Context),
                          unsupported_grant_type_tests(Context),
                          invalid_client_tests(Context),
                          invalid_scope_tests(Context),
                          successful_tests(Context)
                         ] end
    }.

before_tests() ->
    inets:start(),
    ok.

after_tests(_Context) ->
    inets:stop(),
    ok.

%% ===================================================================
%% Tests
%% ===================================================================

bad_request_tests(_Context)->
    Result1 = test_util:request(?CLIENT_TOKEN_URL, post, 
                                []),
    [?_assertEqual(400, test_util:result_status(Result1))
    ].

unauthorized_tests(_Context)->
    Result1 = test_util:request(?CLIENT_TOKEN_URL, post, 
                                [{"grant_type", "client_credentials"},
                                 {"client_id", ?CLIENT1_ID}]),
    Result2 = test_util:request(?CLIENT_TOKEN_URL, post, 
                                [{"grant_type", "client_credentials"},
                                 {"client_secret", ?CLIENT1_SECRET}]),
    [?_assertEqual(401, test_util:result_status(Result1)),
     ?_assertEqual(401, test_util:result_status(Result2))
    ].

invalid_client_tests(_Context)->
    Result1 = test_util:request(?CLIENT_TOKEN_URL, post, 
                                [{"grant_type", "client_credentials"},
                                 {"client_id", "foo"},
                                 {"client_secret", ?CLIENT1_SECRET}]),
    Result2 = test_util:request(?CLIENT_TOKEN_URL, post, 
                                [{"grant_type", "client_credentials"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"client_secret", "foo"}]),
    Result3 = test_util:request(?CLIENT_TOKEN_URL, post,
                                [{"Authorization",
                                  ?BASIC_CREDENTIALS(?CLIENT1_ID, "foo")}],
                                [{"grant_type", "client_credentials"},
                                 {"redirect_uri", ?CLIENT1_URI}]),
    Result4 = test_util:request(?CLIENT_TOKEN_URL, post,
                                [{"Authorization",
                                  ?BASIC_CREDENTIALS("foo", ?CLIENT1_SECRET)}],
                                [{"grant_type", "client_credentials"},
                                 {"redirect_uri", ?CLIENT1_URI}]),
    BodyProplist1 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result1)),
    BodyProplist2 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result2)),
    BodyProplist3 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result3)),
    BodyProplist4 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result4)),
    [?_assertEqual(401, test_util:result_status(Result1)),
     ?_assertEqual(1, length(BodyProplist1)),
     ?_assertEqual("invalid_client", proplists:get_value("error",
                                                         BodyProplist1)),
     ?_assertEqual(401, test_util:result_status(Result2)),
     ?_assertEqual(1, length(BodyProplist2)),
     ?_assertEqual("invalid_client", proplists:get_value("error", 
                                                         BodyProplist2)),
     ?_assertEqual(401, test_util:result_status(Result3)),
     ?_assertEqual(1, length(BodyProplist3)),
     ?_assertEqual("invalid_client", proplists:get_value("error", 
                                                         BodyProplist3)),
     ?_assertEqual(401, test_util:result_status(Result4)),
     ?_assertEqual(1, length(BodyProplist4)),
     ?_assertEqual("invalid_client", proplists:get_value("error", 
                                                         BodyProplist4))
    ].

unsupported_grant_type_tests(_Context) ->
    Result1 = test_util:request(?CLIENT_TOKEN_URL, post, 
                                [{"grant_type", "foo"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"client_secret", ?CLIENT1_SECRET},
                                 {"scope", ?CLIENT1_SCOPE}]),
    BodyProplist1 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result1)),
    [?_assertEqual(400, test_util:result_status(Result1)),
     ?_assertEqual(1, length(BodyProplist1)),
     ?_assertEqual("unsupported_grant_type", 
                   proplists:get_value("error", BodyProplist1))
    ].

invalid_scope_tests(_Context) ->
    Result1 = test_util:request(?CLIENT_TOKEN_URL, post, 
                                [{"grant_type", "client_credentials"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"client_secret", ?CLIENT1_SECRET},
                                 {"scope", "foo"}]),
    BodyProplist1 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result1)),
    [?_assertEqual(400, test_util:result_status(Result1)),
     ?_assertEqual(1, length(BodyProplist1)),
     ?_assertEqual("invalid_scope", 
                   proplists:get_value("error", BodyProplist1))
    ].

successful_tests(_Context)->
    Result1 = test_util:request(?CLIENT_TOKEN_URL, post, 
                                [{"grant_type", "client_credentials"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"client_secret", ?CLIENT1_SECRET},
                                 {"scope", ?CLIENT1_SCOPE}]),
    Result2 = test_util:request(?CLIENT_TOKEN_URL, post,
                                [{"Authorization",
                                  ?BASIC_CREDENTIALS(?CLIENT1_ID, 
                                                     ?CLIENT1_SECRET)}],
                                [{"grant_type", "client_credentials"},
                                 {"scope", ?CLIENT1_SCOPE2}]),
    BodyProplist1 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result1)),
    BodyProplist2 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result2)),
    [?_assertEqual(200, test_util:result_status(Result1)),
     ?_assertEqual(4, length(BodyProplist1)),
     ?_assertNotEqual(undefined, proplists:get_value("access_token",
                                                     BodyProplist1)),
     ?_assertEqual("bearer", proplists:get_value("token_type",
                                                 BodyProplist1)),
     ?_assertEqual("3600", proplists:get_value("expires_in", BodyProplist1)),
     ?_assertEqual(?CLIENT1_SCOPE, proplists:get_value("scope", 
                                                       BodyProplist1)),
     ?_assertEqual(200, test_util:result_status(Result2)),
     ?_assertEqual(4, length(BodyProplist2)),
     ?_assertNotEqual(undefined, proplists:get_value("access_token",
                                                     BodyProplist2)),
     ?_assertEqual("bearer", proplists:get_value("token_type",
                                                 BodyProplist2)),
     ?_assertEqual("3600", proplists:get_value("expires_in", BodyProplist2)),
     ?_assertEqual(?CLIENT1_SCOPE2, proplists:get_value("scope", 
                                                       BodyProplist2))
    ].
