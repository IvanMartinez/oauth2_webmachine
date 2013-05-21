%% @author https://github.com/IvanMartinez
%% @doc @todo Add description to register_processor_tests.

-module(authorization_code_test).

-include_lib("eunit/include/eunit.hrl").
-include("../include/oauth2_request.hrl").

-define(PATH, "/authorization_code").
-define(CONTEXT, whatever).
-define(CLIENT1_ID, "Id1").
-define(CLIENT2_ID, "Id2").
-define(CLIENT2_URI, "Uri2").
-define(CLIENT2_SCOPE, [<<"root.a">>, <<"root.b.*">>]).
-define(REQUEST1_ID, "Request1ID").
-define(REQUEST2_ID, "Request2ID").
-define(STATE, "State").

%% ===================================================================
%% Setup functions
%% ===================================================================

setup_test_() ->
    {setup, 
        fun before_tests/0,
        fun after_tests/1,
        fun (Config) -> [bad_request_tests(Config),
                         unauthorized_tests(Config),
                         unauthorized_client_tests(Config),
                         invalid_redirection_uri_tests(Config),
                         invalid_request_tests(Config),
                         unsupported_response_type_tests(Config),
                         successful_tests(Config)
                        ] end
    }.

before_tests() ->
    meck:new(oauth2_config),
    meck:expect(oauth2_config, backend, fun() -> oauth2_ets_backend end),
    meck:expect(oauth2_config, expiry_time, fun(_) -> 3600 end),
    meck:expect(oauth2_config, token_generation, fun() -> oauth2_token end),
    meck:new(oauth2_token),
    meck:expect(oauth2_token, generate, fun(_) -> <<?REQUEST1_ID>> end),
    oauth2_ets_backend:start(),
    oauth2_ets_backend:add_client(<<?CLIENT1_ID>>, <<>>, <<>>, []),
    oauth2_ets_backend:add_client(<<?CLIENT2_ID>>, <<>>, <<?CLIENT2_URI>>, 
                                  ?CLIENT2_SCOPE),
    ok.

after_tests(_Config) ->
    oauth2_ets_backend:delete_client(?CLIENT1_ID),
    oauth2_ets_backend:delete_client(?CLIENT2_ID),
    oauth2_ets_backend:stop(),
    meck:unload(oauth2_token),
    meck:unload(oauth2_config),
    ok.

%% ===================================================================
%% Tests
%% ===================================================================

bad_request_tests(_Config)->
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"scope", "root.b.c"}], []),
    {Result2, _Response2, Context2} = authorization_code:process_get(Request2, 
                                                                  ?CONTEXT),
    [?_assertEqual({halt, 400}, Result2),
     ?_assertEqual(?CONTEXT, Context2)
    ].

unauthorized_tests(_Config)->
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"client_id", "foo"}], []),
    {Result2, _Response2, Context2} = authorization_code:process_get(Request2, 
                                                                  ?CONTEXT),
    [?_assertEqual({halt, 401}, Result2),
     ?_assertEqual(?CONTEXT, Context2)
    ].

unauthorized_client_tests(_Config)->
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"client_id", ?CLIENT1_ID}], []),
    {Result2, _Response2, Context2} = authorization_code:process_get(Request2, 
                                                                  ?CONTEXT),
    [?_assertEqual({halt, 403}, Result2),
     ?_assertEqual(?CONTEXT, Context2)
    ].

invalid_redirection_uri_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"client_id", ?CLIENT2_ID},
                                       {"redirect_uri", "foo"}], []),
    {Result1, _Response1, Context1} = authorization_code:process_get(Request1, 
                                                                  ?CONTEXT),
    [?_assertEqual({halt, 401}, Result1),
     ?_assertEqual(?CONTEXT, Context1)
    ].

invalid_request_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"client_id", ?CLIENT2_ID}], []),
    {Result1, Response1, Context1} = authorization_code:process_get(Request1, 
                                                                  ?CONTEXT),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"client_id", ?CLIENT2_ID},
                                       {"redirect_uri", ?CLIENT2_URI},
                                       {"scope", "root.a root.b.*"},
                                       {"state", ?STATE}], []),
    {Result2, Response2, Context2} = authorization_code:process_get(Request2, 
                                                                  ?CONTEXT),
    [?_assertEqual({halt, 302}, Result1),
     ?_assertEqual(?CLIENT2_URI ++"?error=invalid_request", 
                   wrq:get_resp_header("Location", Response1)),
     ?_assertEqual(?CONTEXT, Context1),
     ?_assertEqual({halt, 302}, Result2),
     ?_assertEqual(?CLIENT2_URI ++"?error=invalid_request&state=" ++ ?STATE, 
                   wrq:get_resp_header("Location", Response2)),
     ?_assertEqual(?CONTEXT, Context2)
     ].

unsupported_response_type_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "password"},
                                       {"client_id", ?CLIENT2_ID}], []),
    {Result1, Response1, Context1} = authorization_code:process_get(Request1, 
                                                                  ?CONTEXT),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "password"},
                                       {"client_id", ?CLIENT2_ID},
                                       {"redirect_uri", ?CLIENT2_URI},
                                       {"scope", "root.a root.b.*"},
                                       {"state", ?STATE}], []),
    {Result2, Response2, Context2} = authorization_code:process_get(Request2, 
                                                                  ?CONTEXT),
    [?_assertEqual({halt, 302}, Result1),
     ?_assertEqual(?CLIENT2_URI ++"?error=unsupported_response_type", 
                   wrq:get_resp_header("Location", Response1)),
     ?_assertEqual(?CONTEXT, Context1),
     ?_assertEqual({halt, 302}, Result2),
     ?_assertEqual(?CLIENT2_URI ++"?error=unsupported_response_type&state=" ++
                       ?STATE, 
                   wrq:get_resp_header("Location", Response2)),
     ?_assertEqual(?CONTEXT, Context2)
     ].

successful_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"client_id", ?CLIENT2_ID}],
                                      []),
    {Result1, _Response1, Context1}  = authorization_code:process_get(Request1, 
                                                                   ?CONTEXT),
    {ok, StoredRequest1} = oauth2_ets_backend:retrieve_request(<<?REQUEST1_ID>>),
    meck:expect(oauth2_token, generate, fun(_) -> <<?REQUEST2_ID>> end),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"client_id", ?CLIENT2_ID},
                                       {"redirect_uri", ?CLIENT2_URI},
                                       {"scope", "root.a root.b.*"},
                                       {"state", ?STATE}],
                                      []),
    {Result3, _Response3, Context3}  = authorization_code:process_get(Request3, 
                                                                   ?CONTEXT),
    {ok, StoredRequest3} = oauth2_ets_backend:retrieve_request(<<?REQUEST2_ID>>),
    [?_assertEqual({halt, 200}, Result1),
     ?_assertEqual(?CONTEXT, Context1),
     ?_assertEqual(#oauth2_request{client_id = <<?CLIENT2_ID>>, 
                                   redirect_uri = <<?CLIENT2_URI>>,
                                   scope = undefined, state = undefined},
                   StoredRequest1),
     ?_assertEqual({halt, 200}, Result3),
     ?_assertEqual(?CONTEXT, Context3),
     ?_assertEqual(#oauth2_request{client_id = <<?CLIENT2_ID>>, 
                                   redirect_uri = <<?CLIENT2_URI>>, 
                                   scope = ?CLIENT2_SCOPE, 
                                   state = <<?STATE>>}, StoredRequest3)
    ].
