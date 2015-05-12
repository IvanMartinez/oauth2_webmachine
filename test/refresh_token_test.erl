%% @author https://github.com/IvanMartinez
%% @doc Tests for refresh_token resource.
%% @todo Add tests for timed-out grants.

-module(refresh_token_test).

-include_lib("eunit/include/eunit.hrl").

-define(AUTHORIZATION_CODE_URL, "http://127.0.0.1:8000/authorization_code").
-define(ACCESS_TOKEN_URL, "http://127.0.0.1:8000/access_token").
-define(REFRESH_TOKEN_URL, "http://127.0.0.1:8000/refresh_token").
-define(PATH, "/access_token").
-define(STATE, "State").
-define(CLIENT1_ID, "Client1").
-define(CLIENT1_SECRET, "Secret1").
-define(CLIENT1_URI, "http://client.uri").
-define(CLIENT1_SCOPE, "root1.z root2.a").
-define(USER1_USERNAME, "User1").
-define(USER1_PASSWORD, "Password1").
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
                          invalid_client_tests(Context),
                          unsupported_grant_type_tests(Context),
                          invalid_grant_tests(Context),
                          successful_tests(Context)
                         ]
        end
    }.

before_tests() ->
    inets:start(),
    CodeResult1 = test_util:request(?AUTHORIZATION_CODE_URL, post,
                                    [{"response_type", "code"},
                                     {"client_id", ?CLIENT1_ID},
                                     {"redirect_uri", ?CLIENT1_URI},
                                     {"scope", ?CLIENT1_SCOPE},
                                     {"username", ?USER1_USERNAME},
                                     {"password", ?USER1_PASSWORD}]),
    CodeResult2 = test_util:request(?AUTHORIZATION_CODE_URL, post,
                                    [{"response_type", "code"},
                                     {"client_id", ?CLIENT1_ID},
                                     {"redirect_uri", ?CLIENT1_URI},
                                     {"scope", ?CLIENT1_SCOPE},
                                     {"username", ?USER1_USERNAME},
                                     {"password", ?USER1_PASSWORD}]),
    {_, LocationParams1} = test_util:split_url(test_util:result_location(
                                                 CodeResult1)),
    {_, LocationParams2} = test_util:split_url(test_util:result_location(
                                                 CodeResult2)),
    Code1 = proplists:get_value("code", LocationParams1),
    Code2 = proplists:get_value("code", LocationParams2),
    TokenResult1 = test_util:request(?ACCESS_TOKEN_URL, post,
                                     [{"grant_type", "authorization_code"},
                                      {"code", Code1},
                                      {"redirect_uri", ?CLIENT1_URI},
                                      {"client_id", ?CLIENT1_ID},
                                      {"client_secret", ?CLIENT1_SECRET}]),
    TokenResult2 = test_util:request(?ACCESS_TOKEN_URL, post,
                                     [{"Authorization",
                                       ?BASIC_CREDENTIALS(?CLIENT1_ID,
                                                          ?CLIENT1_SECRET)}],
                                     [{"grant_type", "authorization_code"},
                                      {"code", Code2},
                                      {"redirect_uri", ?CLIENT1_URI}]),
    BodyProplist1 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        TokenResult1)),
    BodyProplist2 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        TokenResult2)),
    {proplists:get_value("refresh_token", BodyProplist1),
     proplists:get_value("refresh_token", BodyProplist2)}.

after_tests(_Context) ->
    inets:stop(),
    ok.

%% ===================================================================
%% Tests
%% ===================================================================

bad_request_tests({_Token1, Token2})->
    Result1 = test_util:request(?REFRESH_TOKEN_URL, post, 
                                [{"refresh_token", Token2}]),
    Result2 = test_util:request(?REFRESH_TOKEN_URL, post, 
                                [{"grant_type", "refresh_token"}]),
    [?_assertEqual(400, test_util:result_status(Result1)),
     ?_assertEqual(400, test_util:result_status(Result2))
    ].

unauthorized_tests({Token1, Token2})->
    Result1 = test_util:request(?REFRESH_TOKEN_URL, post, 
                                [{"grant_type", "refresh_token"},
                                 {"refresh_token", Token1},
                                 {"client_id", ?CLIENT1_ID}]),
    Result2 = test_util:request(?REFRESH_TOKEN_URL, post, 
                                [{"grant_type", "refresh_token"},
                                 {"refresh_token", Token2},
                                 {"client_secret", ?CLIENT1_SECRET}]),
    [?_assertEqual(401, test_util:result_status(Result1)),
     ?_assertEqual(401, test_util:result_status(Result2))
    ].

invalid_client_tests({Token1, Token2})->
    Result1 = test_util:request(?REFRESH_TOKEN_URL, post, 
                                [{"grant_type", "refresh_token"},
                                 {"refresh_token", Token1},
                                 {"client_id", "foo"},
                                 {"client_secret", ?CLIENT1_SECRET}]),
    Result2 = test_util:request(?REFRESH_TOKEN_URL, post, 
                                [{"grant_type", "refresh_token"},
                                 {"refresh_token", Token2},
                                 {"client_id", ?CLIENT1_ID},
                                 {"client_secret", "foo"}]),
    Result3 = test_util:request(?REFRESH_TOKEN_URL, post,
                                [{"Authorization",
                                  ?BASIC_CREDENTIALS(?CLIENT1_ID, "foo")}],
                                [{"grant_type", "refresh_token"},
                                 {"refresh_token", Token1}]),
    Result4 = test_util:request(?REFRESH_TOKEN_URL, post,
                                [{"Authorization",
                                  ?BASIC_CREDENTIALS("foo", ?CLIENT1_SECRET)}],
                                [{"grant_type", "refresh_token"},
                                 {"refresh_token", Token2}]),
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

unsupported_grant_type_tests({Token1, _Token2})->
    Result1 = test_util:request(?REFRESH_TOKEN_URL, post, 
                                [{"grant_type", "foo"},
                                 {"refresh_token", Token1},
                                 {"client_id", ?CLIENT1_ID},
                                 {"client_secret", ?CLIENT1_SECRET}]),
    BodyProplist1 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result1)),
    [?_assertEqual(400, test_util:result_status(Result1)),
     ?_assertEqual(1, length(BodyProplist1)),
     ?_assertEqual("unsupported_grant_type", proplists:get_value(
                     "error", BodyProplist1))
    ].

invalid_grant_tests(_Context)->
    Result1 = test_util:request(?REFRESH_TOKEN_URL, post, 
                                [{"grant_type", "refresh_token"},
                                 {"refresh_token", "foo"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"client_secret", ?CLIENT1_SECRET}]),
    Result2 = test_util:request(?REFRESH_TOKEN_URL, post,
                                [{"Authorization",
                                  ?BASIC_CREDENTIALS(?CLIENT1_ID, 
                                                     ?CLIENT1_SECRET)}],
                                [{"grant_type", "refresh_token"},
                                 {"refresh_token", "foo"}]),
    BodyProplist1 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result1)),
    BodyProplist2 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result2)),
    [?_assertEqual(400, test_util:result_status(Result1)),
     ?_assertEqual(1, length(BodyProplist1)),
     ?_assertEqual("invalid_grant", proplists:get_value("error", 
                                                        BodyProplist1)),
     ?_assertEqual(400, test_util:result_status(Result2)),
     ?_assertEqual(1, length(BodyProplist2)),
     ?_assertEqual("invalid_grant", proplists:get_value("error",
                                                        BodyProplist2))
    ].

successful_tests({Token1, Token2})->    
    Result1 = test_util:request(?REFRESH_TOKEN_URL, post, 
                                [{"grant_type", "refresh_token"},
                                 {"refresh_token", Token1},
                                 {"client_id", ?CLIENT1_ID},
                                 {"client_secret", ?CLIENT1_SECRET}]),
    Result2 = test_util:request(?REFRESH_TOKEN_URL, post,
                                [{"Authorization",
                                  ?BASIC_CREDENTIALS(?CLIENT1_ID, 
                                                     ?CLIENT1_SECRET)}],
                                [{"grant_type", "refresh_token"},
                                 {"refresh_token", Token2},
                                 {"redirect_uri", ?CLIENT1_URI}]),
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
     ?_assertEqual(?CLIENT1_SCOPE, proplists:get_value("scope", BodyProplist1)),
     ?_assertEqual(200, test_util:result_status(Result2)),
     ?_assertEqual(4, length(BodyProplist2)),
     ?_assertNotEqual(undefined, proplists:get_value("access_token",
                                                     BodyProplist2)),
     ?_assertEqual("bearer", proplists:get_value("token_type",
                                                 BodyProplist2)),
     ?_assertEqual("3600", proplists:get_value("expires_in", BodyProplist2)),
     ?_assertEqual(?CLIENT1_SCOPE, proplists:get_value("scope", BodyProplist2))
    ].
