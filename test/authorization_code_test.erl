%% @author https://github.com/IvanMartinez
%% @doc @todo Add description to register_processor_tests.

-module(authorization_code_test).

-include_lib("eunit/include/eunit.hrl").
-include("../include/oauth2_request.hrl").

-define(PATH, "/authorization_code").
-define(CONTEXT, whatever).
-define(CLIENT1ID, "Id1").
-define(CLIENT2ID, "Id2").
-define(CLIENT2URI, "Uri2").
-define(CLIENT2SCOPE, [<<"root.a">>, <<"root.b.*">>]).
-define(REQUEST1ID, "REQUEST1ID").
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
    meck:new(oauth2_token),
    meck:expect(oauth2_token, generate, fun() -> <<?REQUEST1ID>> end),
    oauth2_ets_backend:start(),
    oauth2_ets_backend:add_client(<<?CLIENT1ID>>, <<>>, <<>>, []),
    oauth2_ets_backend:add_client(<<?CLIENT2ID>>, <<>>, <<?CLIENT2URI>>, 
                                  ?CLIENT2SCOPE),
    ok.

after_tests(_Config) ->
    oauth2_ets_backend:delete_client(?CLIENT1ID),
    oauth2_ets_backend:delete_client(?CLIENT2ID),
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
                                       {"client_id", ?CLIENT1ID}], []),
    {Result2, _Response2, Context2} = authorization_code:process_get(Request2, 
                                                                  ?CONTEXT),
    [?_assertEqual({halt, 403}, Result2),
     ?_assertEqual(?CONTEXT, Context2)
    ].

invalid_redirection_uri_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"client_id", ?CLIENT2ID},
                                       {"redirect_uri", "foo"}], []),
    {Result1, _Response1, Context1} = authorization_code:process_get(Request1, 
                                                                  ?CONTEXT),
    [?_assertEqual({halt, 401}, Result1),
     ?_assertEqual(?CONTEXT, Context1)
    ].

invalid_request_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"client_id", ?CLIENT2ID}], []),
    {Result1, Response1, Context1} = authorization_code:process_get(Request1, 
                                                                  ?CONTEXT),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"client_id", ?CLIENT2ID},
                                       {"redirect_uri", ?CLIENT2URI},
                                       {"scope", "root.a root.b.*"},
                                       {"state", ?STATE}], []),
    {Result2, Response2, Context2} = authorization_code:process_get(Request2, 
                                                                  ?CONTEXT),
    [?_assertEqual({halt, 302}, Result1),
     ?_assertEqual(?CLIENT2URI ++"?error=invalid_request", 
                   wrq:get_resp_header("Location", Response1)),
     ?_assertEqual(?CONTEXT, Context1),
     ?_assertEqual({halt, 302}, Result2),
     ?_assertEqual(?CLIENT2URI ++"?error=invalid_request&state=" ++ ?STATE, 
                   wrq:get_resp_header("Location", Response2)),
     ?_assertEqual(?CONTEXT, Context2)
     ].

unsupported_response_type_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "password"},
                                       {"client_id", ?CLIENT2ID}], []),
    {Result1, Response1, Context1} = authorization_code:process_get(Request1, 
                                                                  ?CONTEXT),
    Request2 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "password"},
                                       {"client_id", ?CLIENT2ID},
                                       {"redirect_uri", ?CLIENT2URI},
                                       {"scope", "root.a root.b.*"},
                                       {"state", ?STATE}], []),
    {Result2, Response2, Context2} = authorization_code:process_get(Request2, 
                                                                  ?CONTEXT),
    [?_assertEqual({halt, 302}, Result1),
     ?_assertEqual(?CLIENT2URI ++"?error=unsupported_response_type", 
                   wrq:get_resp_header("Location", Response1)),
     ?_assertEqual(?CONTEXT, Context1),
     ?_assertEqual({halt, 302}, Result2),
     ?_assertEqual(?CLIENT2URI ++"?error=unsupported_response_type&state=" ++
                       ?STATE, 
                   wrq:get_resp_header("Location", Response2)),
     ?_assertEqual(?CONTEXT, Context2)
     ].

successful_tests(_Config)->
    Request1 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"client_id", ?CLIENT2ID}],
                                      []),
    {Result1, _Response1, Context1}  = authorization_code:process_get(Request1, 
                                                                   ?CONTEXT),
    {ok, StoredRequest1} = oauth2_ets_backend:retrieve_request(<<?REQUEST1ID>>),
    Request3 = test_util:make_get_wrq(?PATH, 
                                      [{"response_type", "code"},
                                       {"client_id", ?CLIENT2ID},
                                       {"redirect_uri", ?CLIENT2URI},
                                       {"scope", "root.a root.b.*"},
                                       {"state", ?STATE}],
                                      []),
    {Result3, _Response3, Context3}  = authorization_code:process_get(Request3, 
                                                                   ?CONTEXT),
    {ok, StoredRequest3} = oauth2_ets_backend:retrieve_request(<<?REQUEST1ID>>),
    [?_assertEqual({halt, 200}, Result1),
     ?_assertEqual(?CONTEXT, Context1),
     ?_assertEqual(#oauth2_request{client_id = <<?CLIENT2ID>>, 
                                   redirect_uri = <<?CLIENT2URI>>,
                                   scope = undefined, state = undefined},
                   StoredRequest1),
     ?_assertEqual({halt, 200}, Result3),
     ?_assertEqual(?CONTEXT, Context3),
     ?_assertEqual(#oauth2_request{client_id = <<?CLIENT2ID>>, 
                                   redirect_uri = <<?CLIENT2URI>>, 
                                   scope = ?CLIENT2SCOPE, 
                                   state = <<?STATE>>}, StoredRequest3)
    ].
