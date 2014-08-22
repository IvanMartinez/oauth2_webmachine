%% @author https://github.com/IvanMartinez
%% @doc Tests for authorization_code resource.

-module(authorization_code_test).

-include_lib("eunit/include/eunit.hrl").

-define(AUTHORIZATION_CODE_URL, "http://127.0.0.1:8000/authorization_code").
-define(CLIENT1_ID, "Client1").
-define(CLIENT1_URI, "http://client.uri").
-define(CLIENT1_SCOPE, "root1.z root2.a").
-define(USER1_USERNAME, "User1").
-define(USER1_PASSWORD, "Password1").
-define(STATE, "State").

%% ===================================================================
%% Setup functions
%% ===================================================================

setup_test_() ->
    {setup, 
        fun before_tests/0,
        fun after_tests/1,
        fun (Context) -> [bad_request_tests(Context),
                          unauthorized_client_tests(Context),
                          unsupported_response_type_tests(Context),
                          invalid_scope_tests(Context),
                          access_denied_tests(Context),
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
    Result1 = test_util:request(?AUTHORIZATION_CODE_URL, get, 
                                [{"client_id", ?CLIENT1_ID},
                                 {"redirect_uri", ?CLIENT1_URI}]),
    Result2 = test_util:request(?AUTHORIZATION_CODE_URL, get, 
                                [{"response_type", "code"},
                                 {"redirect_uri", ?CLIENT1_URI}]),
    Result3 = test_util:request(?AUTHORIZATION_CODE_URL, get, 
                                [{"response_type", "code"},
                                 {"client_id", ?CLIENT1_ID}]),
    Result4 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"client_id", ?CLIENT1_ID},
                                 {"redirect_uri", ?CLIENT1_URI},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD}]),
    Result5 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "code"},
                                 {"redirect_uri", ?CLIENT1_URI},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD}]),
    Result6 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "code"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD}]),
    Result7 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "code"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"redirect_uri", ?CLIENT1_URI},
                                 {"password", ?USER1_PASSWORD}]),
    Result8 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "code"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"redirect_uri", ?CLIENT1_URI},
                                 {"username", ?USER1_USERNAME}]),
    [?_assertEqual(400, test_util:result_status(Result1)),
     ?_assertEqual(400, test_util:result_status(Result2)),
     ?_assertEqual(400, test_util:result_status(Result3)),
     ?_assertEqual(400, test_util:result_status(Result4)),
     ?_assertEqual(400, test_util:result_status(Result5)),
     ?_assertEqual(400, test_util:result_status(Result6)),
     ?_assertEqual(400, test_util:result_status(Result7)),
     ?_assertEqual(400, test_util:result_status(Result8))
    ].

unauthorized_client_tests(_Context)->
    Result1 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "code"},
                                 {"client_id", "foo"},
                                 {"redirect_uri", ?CLIENT1_URI},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD}]),
    Result2 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "code"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"redirect_uri", "foo"},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD}]),
    [?_assertEqual(403, test_util:result_status(Result1)),
     ?_assertEqual(403, test_util:result_status(Result2))
    ].

unsupported_response_type_tests(_Config) ->
    Result1 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "foo"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"redirect_uri", ?CLIENT1_URI},
                                 {"scope", ?CLIENT1_SCOPE},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD},
                                 {"state", ?STATE}]),
    {LocationBaseURL1, LocationParams1} = 
        test_util:split_url(test_util:result_location(Result1)),
    [?_assertEqual(302, test_util:result_status(Result1)),
     ?_assertEqual(?CLIENT1_URI, LocationBaseURL1),
     ?_assertEqual(2, length(LocationParams1)),
     ?_assertEqual("unsupported_response_type", 
                   proplists:get_value("error", LocationParams1)),
     ?_assertEqual(?STATE, proplists:get_value("state", LocationParams1))
    ].

invalid_scope_tests(_Context) ->
    Result1 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "code"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"redirect_uri", ?CLIENT1_URI},
                                 {"scope", "foo"},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD},
                                 {"state", ?STATE}]),
    {LocationBaseURL1, LocationParams1} = 
        test_util:split_url(test_util:result_location(Result1)),
    [?_assertEqual(302, test_util:result_status(Result1)),
     ?_assertEqual(?CLIENT1_URI, LocationBaseURL1),
     ?_assertEqual(2, length(LocationParams1)),
     ?_assertEqual("invalid_scope", 
                   proplists:get_value("error", LocationParams1)),
     ?_assertEqual(?STATE, proplists:get_value("state", LocationParams1))
    ].

access_denied_tests(_Context) ->
    Result1 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "code"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"redirect_uri", ?CLIENT1_URI},
                                 {"scope", ?CLIENT1_SCOPE},
                                 {"username", "foo"},
                                 {"password", ?USER1_PASSWORD},
                                 {"state", ?STATE}]),
    Result2 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "code"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"redirect_uri", ?CLIENT1_URI},
                                 {"scope", ?CLIENT1_SCOPE},
                                 {"username", ?USER1_USERNAME},
                                 {"password", "foo"}]),
    {LocationBaseURL1, LocationParams1} = 
        test_util:split_url(test_util:result_location(Result1)),
    {LocationBaseURL2, LocationParams2} = 
        test_util:split_url(test_util:result_location(Result2)),
    [?_assertEqual(302, test_util:result_status(Result1)),
     ?_assertEqual(?CLIENT1_URI, LocationBaseURL1),
     ?_assertEqual(2, length(LocationParams1)),
     ?_assertEqual("access_denied", 
                   proplists:get_value("error", LocationParams1)),
     ?_assertEqual(?STATE, proplists:get_value("state", LocationParams1)),
     ?_assertEqual(302, test_util:result_status(Result2)),
     ?_assertEqual(?CLIENT1_URI, LocationBaseURL2),
     ?_assertEqual(1, length(LocationParams2)),
     ?_assertEqual("access_denied", 
                   proplists:get_value("error", LocationParams2))
    ].

successful_tests(_Context)->
    Result1 = test_util:request(?AUTHORIZATION_CODE_URL, post, 
                                [{"response_type", "code"},
                                 {"client_id", ?CLIENT1_ID},
                                 {"redirect_uri", ?CLIENT1_URI},
                                 {"scope", ?CLIENT1_SCOPE},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD},
                                 {"state", ?STATE}]),
    {LocationBaseURL, LocationParams} = 
        test_util:split_url(test_util:result_location(Result1)),
    [?_assertEqual(302, test_util:result_status(Result1)),
     ?_assertEqual(?CLIENT1_URI, LocationBaseURL),
     ?_assertEqual(2, length(LocationParams)),
     ?_assertNotEqual(undefined, proplists:get_value("code", LocationParams)),
     ?_assertEqual(?STATE, proplists:get_value("state", LocationParams))
    ].
