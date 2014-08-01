%% @author https://github.com/IvanMartinez
%% @doc Tests for authorization_token resource.

-module(owner_token_test).

-include_lib("eunit/include/eunit.hrl").

-define(OWNER_TOKEN_URL, "http://127.0.0.1:8000/owner_token").
-define(USER1_USERNAME, "User1").
-define(USER1_PASSWORD, "Password1").
-define(USER1_SCOPE, "root1.z root2.a").

%% ===================================================================
%% Setup functions
%% ===================================================================

setup_test_() ->
    {setup, 
        fun before_tests/0,
        fun after_tests/1,
        fun (Config) -> [bad_request_tests(Config),
                         invalid_scope_tests(Config),
                         access_denied_tests(Config),
                         successful_tests(Config)
                        ] end
    }.

before_tests() ->
    inets:start(),
    ok.

after_tests(_Config) ->
    inets:stop(),
    ok.

%% ===================================================================
%% Tests
%% ===================================================================

bad_request_tests(_Config)->
    Result1 = test_util:request(?OWNER_TOKEN_URL, post, 
                                [{"grant_type", "foo"},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD}]),
    Result2 = test_util:request(?OWNER_TOKEN_URL, post, 
                                [{"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD}]),
    Result3 = test_util:request(?OWNER_TOKEN_URL, post, 
                                [{"grant_type", "password"},
                                 {"password", ?USER1_PASSWORD}]),
    Result4 = test_util:request(?OWNER_TOKEN_URL, post, 
                                [{"grant_type", "password"},
                                 {"username", ?USER1_USERNAME}]),
    [?_assertEqual(400, test_util:result_status(Result1)),
     ?_assertEqual(400, test_util:result_status(Result2)),
     ?_assertEqual(400, test_util:result_status(Result3)),
     ?_assertEqual(400, test_util:result_status(Result4))
    ].

invalid_scope_tests(_Config) ->
    Result1 = test_util:request(?OWNER_TOKEN_URL, post, 
                                [{"grant_type", "password"},
                                 {"scope", "foo"},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD}]),
    BodyProplist1 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result1)),
    [?_assertEqual(400, test_util:result_status(Result1)),
     ?_assertEqual(1, length(BodyProplist1)),
     ?_assertEqual("invalid_scope", 
                   proplists:get_value("error", BodyProplist1))
    ].

access_denied_tests(_Config) ->
    Result1 = test_util:request(?OWNER_TOKEN_URL, post, 
                                [{"grant_type", "password"},
                                 {"scope", ?USER1_SCOPE},
                                 {"username", "foo"},
                                 {"password", ?USER1_PASSWORD}]),
    Result2 = test_util:request(?OWNER_TOKEN_URL, post, 
                                [{"grant_type", "password"},
                                 {"scope", ?USER1_SCOPE},
                                 {"username", ?USER1_USERNAME},
                                 {"password", "foo"}]),
    BodyProplist1 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result1)),
    BodyProplist2 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result2)),
    [?_assertEqual(400, test_util:result_status(Result1)),
     ?_assertEqual(1, length(BodyProplist1)),
     ?_assertEqual("access_denied", 
                   proplists:get_value("error", BodyProplist1)),
     ?_assertEqual(400, test_util:result_status(Result2)),
     ?_assertEqual(1, length(BodyProplist2)),
     ?_assertEqual("access_denied", 
                   proplists:get_value("error", BodyProplist2))
    ].

successful_tests(_Config)->
    Result1 = test_util:request(?OWNER_TOKEN_URL, post, 
                                [{"grant_type", "password"},
                                 {"scope", ?USER1_SCOPE},
                                 {"username", ?USER1_USERNAME},
                                 {"password", ?USER1_PASSWORD}]),
    BodyProplist1 = test_util:simple_json_to_proplist(test_util:result_body(
                                                        Result1)),
    [?_assertEqual(200, test_util:result_status(Result1)),
     ?_assertEqual(4, length(BodyProplist1)),
     ?_assertNotEqual(undefined, proplists:get_value("access_token",
                                                     BodyProplist1)),
     ?_assertEqual("bearer", proplists:get_value("token_type",
                                                 BodyProplist1)),
     ?_assertEqual("3600", proplists:get_value("expires_in", BodyProplist1)),
     ?_assertEqual(?USER1_SCOPE, proplists:get_value("scope", 
                                                       BodyProplist1))
    ].
