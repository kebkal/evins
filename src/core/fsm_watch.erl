%% Copyright (c) 2015, Oleksiy Kebkal <lesha@evologics.de>
%% 
%% Redistribution and use in source and binary forms, with or without 
%% modification, are permitted provided that the following conditions 
%% are met: 
%% 1. Redistributions of source code must retain the above copyright 
%%    notice, this list of conditions and the following disclaimer. 
%% 2. Redistributions in binary form must reproduce the above copyright 
%%    notice, this list of conditions and the following disclaimer in the 
%%    documentation and/or other materials provided with the distribution. 
%% 3. The name of the author may not be used to endorse or promote products 
%%    derived from this software without specific prior written permission. 
%% 
%% Alternatively, this software may be distributed under the terms of the 
%% GNU General Public License ("GPL") version 2 as published by the Free 
%% Software Foundation. 
%% 
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR 
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, 
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
-module(fsm_watch).
-behaviour(gen_server).

-include("fsm.hrl").

%% public API
-export([start_link/2]).

%% gen_server callbacks
-export([code_change/3, handle_call/3, handle_cast/2, handle_info/2, init/1, terminate/2]).

-record(watchstate, {sup_id, fabric_config, user_config, status, configured_modules, configuration}).

-define(TIMEOUT, 10000).

signed_config(User_config) ->
    try
	{ok, MD5_read} = file:read_file(User_config ++ ".md5"),
	{ok, Bin} = file:read_file(User_config),
	MD5 = crypto:hash(md5, Bin),
	MD5 == MD5_read
    catch _:_ -> false
    end.
    
choose_config(Fabric_config, User_config) ->
    case signed_config(User_config) of
	true -> User_config;
	_ -> Fabric_config
    end.

consult(Reply, #watchstate{sup_id = Sup_ID, fabric_config = Fabric_config, user_config = User_config} = State) ->
    gen_event:notify(error_logger, {fsm_event, self(), {retry, Fabric_config, User_config}}),
    ConfigFile = choose_config(Fabric_config, User_config),
    case file:consult(ConfigFile) of
    	{ok, ModemDataList} ->
    	    case fsm_supervisor:check_terms(ModemDataList) of
    		[] ->
		    Modules = lists:map(fun(ModemData) ->
				      {module, ID, ModuleConfig} = ModemData,
				      [Name] = [M || {mfa, M, _, _} <- ModuleConfig],
				      {ok, _} = supervisor:start_child(Sup_ID, {ID,
										{fsm_mod_supervisor, start_link, [ModemData]},
										permanent, 1000, supervisor, []}),
				      {Name, ID}
			      end, ModemDataList),
    		    {Reply, State#watchstate{configured_modules = Modules, configuration = ModemDataList}, ?TIMEOUT};
    		Errors ->
    		    error_logger:error_report([{file,?MODULE,?LINE}, "Syntax error: terms check", ConfigFile, Errors]),
    		    {Reply, State, ?TIMEOUT}
    	    end;
    	{error, {Line, Mod, Term}} ->
    	    error_logger:error_report([{file,?MODULE,?LINE}, "Syntax error", ConfigFile, {Line, Mod, Term}]),
    	    {Reply, State, ?TIMEOUT};
    	{error, Why} ->
    	    error_logger:error_report([{file,?MODULE,?LINE}, "Read/access error", ConfigFile, Why]),
    	    {Reply, State, ?TIMEOUT}
    end.

start_link([Fabric_config, User_config], Sup_ID) ->
    gen_server:start_link({local, fsm_watch}, ?MODULE, 
			  #watchstate{sup_id = Sup_ID,
				      fabric_config = Fabric_config,
				      user_config = User_config,
				      status = init,
				      configured_modules = []}, []).

init(State) ->
    {ok, State, 0}.

handle_call(fabric_config, _From, #watchstate{fabric_config = Filename} = State) ->
    {reply, Filename, State};

handle_call(user_config, _From, #watchstate{user_config = Filename} = State) ->
    {reply, Filename, State};

%% TODO: extract Modules from configuration
handle_call(configured_modules, _From, #watchstate{configured_modules = Modules} = State) ->
    {reply, Modules, State};

handle_call({config, Module_ID}, _From, #watchstate{configuration = ModuleList} = State) ->
    {reply,
     lists:foldl(fun({module, ID, ModuleConfig}, _) when ID == Module_ID -> {module, ID, ModuleConfig};
		    (_, Reply) -> Reply
		 end, {error, "Module not found"}, ModuleList),
     State};

handle_call(config, _From, #watchstate{configuration = ModuleList} = State) ->
    {reply, ModuleList, State};

handle_call({module_parameters, Module_ID}, _From, #watchstate{configuration = ModuleList} = State) ->
    {reply,
     lists:foldl(fun({module, ID, ModuleConfig}, _) when ID == Module_ID ->
			 [Opts] = [O || {mfa, _, _, O} <- ModuleConfig],
			 Opts;
		    (_, Reply) -> Reply
		 end, {error, "Module not found"}, ModuleList),
     State};

%% TODO: new parameters should be immediately applied or not?
handle_call({module_parameters, Module_ID, Opts}, _From, #watchstate{configuration = ModuleList} = State) ->
    case lists:keymember(Module_ID, 2, ModuleList) of
	true ->
	    NewModuleList =
		lists:map(fun({module, ID, ModuleConfig}) when ID == Module_ID ->
				  {module, ID,
				   lists:map(fun({mfa, M, F, _}) -> {mfa, M, F, Opts};
						(Other) -> Other
					     end, ModuleConfig)};
			     (Item) -> Item
			  end, ModuleList),
	    {reply, ok, State#watchstate{configuration = NewModuleList}};
	_ ->
	    {reply, {error, "Module not found"}, State}
    end;

handle_call({roles, Module_ID}, _From, #watchstate{configuration = ModuleList} = State) ->
    {reply,
     lists:foldl(fun({module, ID, ModuleConfig}, _) when ID == Module_ID ->
			 lists:filter(fun({role,_,_,_}) -> true;
					 ({role,_,_,_,_,_}) -> true;
					 (_) -> false
				      end, ModuleConfig);
		    (_, Reply) -> Reply
		 end, {error, "Module not found"}, ModuleList),
     State};

%% TODO: new parameters should be immediately applied or not?
handle_call({roles, Module_ID, Role_spec_old, Role_spec_new}, _From, #watchstate{configuration = ModuleList} = State) ->
    case {lists:keymember(Module_ID, 2, ModuleList), fsm_supervisor:check_role(Role_spec_new)} of
	{true, ok} ->
	    {module, Module_ID, ModuleConfigProbe} = lists:keyfind(Module_ID, 2, ModuleList),
	    case lists:member(Role_spec_old, ModuleConfigProbe) of
		true ->
		    NewModuleList =
			lists:map(fun({module, ID, ModuleConfig}) when ID == Module_ID ->
					  {module, ID,
					   lists:map(fun(Role_spec) when Role_spec == Role_spec_old -> Role_spec_new;
							(Other) -> Other
						     end, ModuleConfig)};
				     (Item) -> Item
				  end, ModuleList),
		    {reply, ok, State#watchstate{configuration = NewModuleList}};
		_ ->
		    {reply, {error, "Role spec not found"}, State}
	    end;
	{false, _} ->
	    {reply, {error, "Module not found"}, State};
	{_, Spec_error} ->
	    {reply, Spec_error, State}
    end;

handle_call({mfa, Module_ID}, _From, #watchstate{configuration = ModuleList} = State) ->
    {reply,
     lists:foldl(fun({module, ID, ModuleConfig}, _) when ID == Module_ID -> lists:keyfind(mfa,1,ModuleConfig);
		    (_, Reply) -> Reply
		 end, {error, "Module not found"}, ModuleList),
     State};

handle_call({mfa, Module_ID, MFA_new}, _From, #watchstate{configuration = ModuleList} = State) ->
    case {lists:keymember(Module_ID, 2, ModuleList), fsm_supervisor:check_mfa(MFA_new)} of
	{true, ok} ->
	    NewModuleList =
		lists:map(fun({module, ID, ModuleConfig}) when ID == Module_ID ->
				  {module, ID,
				   lists:map(fun({mfa,_,_,_}) -> MFA_new;
						(Other) -> Other
					     end, ModuleConfig)};
			     (Item) -> Item
			  end, ModuleList),
	    {reply, ok, State#watchstate{configuration = NewModuleList}};
	{false, _} -> {reply, {error, "Module not found"}, State};
	{_, Error} -> {reply, Error, State}
    end;

handle_call({store, Filename}, _From, #watchstate{configuration = ModuleList} = State) ->
    case fsm_supervisor:check_terms(ModuleList) of
	[] ->
	    Store_status = 
		lists:foldl(fun({module, ID, ModuleConfig}, ok) ->
				    SModuleConfig = io_lib:format("~100p.~n", [{module, ID, ModuleConfig}]),
				    file:write_file(Filename, SModuleConfig, [append]);
			       (_, Other) -> Other
			    end, file:write_file(Filename, ""), ModuleList),
	    case {Store_status, file:read_file(Filename)} of
		{ok, {ok, Bin}} ->
		    MD5 = crypto:hash(md5, Bin),
		    MD5_status = file:write_file(Filename ++ ".md5", MD5),
		    {reply,MD5_status,State};
		_ -> {reply,Store_status,State}
	    end;
	Errors ->
	    {reply, Errors, State}
    end;

handle_call({add, Module_spec}, _From, #watchstate{configuration = ModuleList} = State) ->
    case fsm_supervisor:check_terms([Module_spec | ModuleList]) of
	[] -> {reply, ok, State#watchstate{configuration = [Module_spec | ModuleList]}};
	Errors -> {reply, Errors, State}
    end;

handle_call({delete, Module_ID}, _From, #watchstate{configuration = ModuleList} = State) ->
    NewModuleList = lists:filter(fun({module, ID, _}) -> ID /= Module_ID end, ModuleList),
    {reply, ok, State#watchstate{configuration = NewModuleList}};
    
handle_call({module_id, Module_ID, Module_ID_new}, _From, #watchstate{configuration = ModuleList} = State) ->
    NewModuleList = lists:map(fun({module,ID,ModuleConfig}) when ID == Module_ID -> {module,Module_ID_new,ModuleConfig};
				 (Module_spec) -> Module_spec
			      end, ModuleList),    
    {reply, ok, State#watchstate{configuration = NewModuleList}};

handle_call({update_config, Filename}, _From, State) ->
    case signed_config(Filename) of
	true -> {reply, ok, State#watchstate{status = init, configured_modules = [], user_config = Filename}, 0};
	_ -> {reply, {error, badConfig}, State}
    end;

handle_call(Request, From, State) ->
    gen_event:notify(error_logger, {fsm_core, self(), {fsm_watch, call, Request, From, State}}),
    {noreply, State, ?TIMEOUT}.

handle_cast(Request, State) ->
    gen_event:notify(error_logger, {fsm_core, self(), {fsm_watch, cast, Request, State}}),
    {noreply, State, ?TIMEOUT}.

handle_info(timeout, #watchstate{status = init} = State) ->
    consult(noreply, State#watchstate{status = running});

handle_info(timeout, State) ->
    {noreply, State, ?TIMEOUT};

handle_info(Info, State) ->
    gen_event:notify(error_logger, {fsm_core, self(), {fsm_watch, info, Info, State}}),
    {noreply, State, ?TIMEOUT}.

terminate(Reason, State) ->
    gen_event:notify(error_logger, {fsm_core, self(), {fsm_watch, terminate, Reason, State}}),
    ok.

code_change(_, Pid, _) ->
    {ok, Pid}.
