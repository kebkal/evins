-module(log_nl_mac).

-import(lists, [filter/2, foldl/3, map/2, member/2]).
-export([start_parse/2]).

-include("nl.hrl").
-include("log.hrl").

% LogDir has to consist directories for each of experiment:
%  log1, log2, log3 etc, where 1,2,3 - is local address

start_parse(NLProtocol, LogDir) ->
  EtsName = list_to_atom(atom_to_list(results_) ++ atom_to_list(NLProtocol)),
  EtsTable = ets:new(EtsName, [set, named_table]),
  start_parse(EtsTable, NLProtocol, LogDir, ?NODES),
  analyse(EtsTable).

start_parse(_, _, _, []) -> [];
start_parse(EtsTable, NLProtocol, Dir, [HNode | TNodes]) ->
  LogDir = Dir ++ "/log" ++ integer_to_list(HNode),
  {ok, _} = fsm_rb:start([{report_dir, LogDir}]),
  parse_send(HNode, EtsTable, NLProtocol, LogDir),
  fsm_rb:stop(),
  start_parse(EtsTable, NLProtocol, Dir, TNodes).

parse_send(HNode, EtsTable, NL_Protocol, LogDir) ->
  file:delete(LogDir ++ "/parse_send.log"),
  ok = fsm_rb:start_log(LogDir ++ "/parse_send.log"),
  fsm_rb:grep("MAC_AT_SEND"),
  readlines(HNode, EtsTable, NL_Protocol, send, LogDir ++ "/parse_send.log"),

  file:delete(LogDir ++ "/parse_recv.log"),
  ok = fsm_rb:start_log(LogDir ++ "/parse_recv.log"),
  fsm_rb:grep("MAC_AT_RECV"),
  readlines(HNode, EtsTable, NL_Protocol, recv, LogDir ++ "/parse_recv.log").

readlines(HNode, EtsTable, NL_Protocol, Action, FileName) ->
  {ok, Device} = file:open(FileName, [read]),
  try get_all_lines(HNode, EtsTable, NL_Protocol, Action, Device, "")
    after file:close(Device)
  end.

get_all_lines(HNode, EtsTable, NL_Protocol, Action, Device, OLine) ->
  case io:get_line(Device, "") of
    eof  -> [];
    Line ->
      ActionStr =
      case Action of
        send -> "MAC_AT_SEND";
        recv -> "MAC_AT_RECV"
      end,
      {ok, TimeReg} = re:compile("(.*)[0-9]+\.[0-9]+\.[0-9]+(.*)"++ActionStr),
      case re:run(Line, TimeReg, []) of
        {match, _Match} ->
          Time = get_time(OLine),
          RTuple = get_tuple(Action, OLine),
          Payl = get_payl(OLine),
          extract_payl(HNode, EtsTable, Action, RTuple, NL_Protocol, Time, Payl),
          get_all_lines(HNode, EtsTable, NL_Protocol, Action, Device, Line);
        nomatch ->
          get_all_lines(HNode, EtsTable, NL_Protocol, Action, Device, OLine ++ Line)
      end
  end.

get_time(Line) ->
  {ok, TimeReg} = re:compile("[0-9]+\.[0-9]+\.[0-9]+"),
  case re:run(Line, TimeReg, [{capture, first, list}]) of
    {match, Match} ->
      [Time] = Match,
      {match, [BMega, BSec, BMicro]} =
      re:run(Time, "([^.]*).([^.]*).([^.]*)", [dotall,{capture, all_but_first, binary}]),
      Mega = bin_to_num(BMega),
      Sec = bin_to_num(BSec),
      Micro = bin_to_num(BMicro),
      Mega * 1000000 * 1000000 + Sec * 1000000 + Micro;
    nomatch -> nothing
  end.


get_tuple(send, _Line) ->
  nothing;
get_tuple(recv, Line) ->
  RecvRegexp = "recvim,([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),(.*),.*",
  case re:run(Line, RecvRegexp, [dotall,{capture, all_but_first, binary}]) of
    {match, [_, BSrc, BDst, _, _, BRssi, BIntegrity,_]} ->
      Src = bin_to_num(BSrc),
      Dst = bin_to_num(BDst),
      Rssi = bin_to_num(BRssi),
      Integrity = bin_to_num(BIntegrity),
      [Src, Dst, Rssi, Integrity];
    nomatch -> nothing
  end.

get_payl(Line) ->
  case re:run(Line, "<<(.*)>>", [{capture, first, list}]) of
    {match, Match} ->
      S = re:replace(Match,"<<|>>","",[global, {return,list}]),
      LInt = lists:map(fun(X) -> {Int, _} = string:to_integer(X), Int end, string:tokens(S, ",")),
      lists:foldr(fun(X, A) -> <<X, A/binary>> end, <<>>, LInt);
    nomatch -> nothing
  end.

extract_payl(_, _, _, _, _, _, nothing) ->
  [];
extract_payl(_HNode, _EtsTable, send, _STuple, icrpr, Time, Payl) ->
  [Flag, PkgID, Dst, Src, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
  case nl_mac_hf:num2flag(Flag, nl) of
    data ->
      [Path, BData] = nl_mac_hf:extract_path_data(nothing, Data),
      io:format("SEND ~p ~p ~p ~p ~p ~p ~p ~n", [nl_mac_hf:num2flag(Flag, nl), Time, PkgID, Dst, Src, Path, BData]);
    ack ->
      nothing;
    dst_reached ->
      nothing
  end;
extract_payl(_HNode,_EtsTable, recv, RTuple, icrpr, Time, Payl) ->
  if RTuple == nothing;
     Payl == <<>> ->
    nothing;
  true ->
    [RSrc, RDst, Rssi, Integrity] = RTuple,
    [Flag, PkgID, Dst, Src, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
    case nl_mac_hf:num2flag(Flag, nl) of
      data ->
        [Path, BData] = nl_mac_hf:extract_path_data(nothing, Data),
        io:format("RECV ~p ~p ~p ~p ~p ~p ~p ~p ~p ~p ~n", [Time, RSrc, RDst, Rssi, Integrity, PkgID, Dst, Src, Path, BData]);
      ack ->
        nothing;
      dst_reached ->
        nothing
    end
  end;
extract_payl(HNode, EtsTable, send, _STuple, sncfloodr, Time, Payl) ->
  [Flag, PkgID, Dst, Src, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
  case nl_mac_hf:num2flag(Flag, nl) of
    data ->
      add_data(EtsTable, {PkgID, Data, Src, Dst}, {send, HNode, Time});
    dst_reached ->
      nothing
  end;
extract_payl(HNode, EtsTable, recv, RTuple, sncfloodr, Time, Payl) ->
  if RTuple == nothing;
     Payl == <<>> ->
    nothing;
  true ->
    [RSrc, RDst, Rssi, Integrity] = RTuple,
    [Flag, PkgID, Dst, Src, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
    case nl_mac_hf:num2flag(Flag, nl) of
      data ->
        add_data(EtsTable, {PkgID, Data, Src, Dst}, {recv, HNode, Time, RSrc, RDst, Rssi, Integrity});
      ack ->
        nothing;
      dst_reached ->
        nothing
    end
  end.

% IdTuple = {PkgID, Data, Src, Dst}
% {send, RSrc, TimeSend}
% {recv, HNode, TimeRecv, RSrc, RDst, Rssi, Integrity}
add_data(EtsTable, IdTuple, VTuple) ->
  LookEts = ets:lookup(EtsTable, IdTuple),

  case LookEts of
    [{IdTuple, {{nodes_sent, Ns},
              {nodes_recv, Nr},
              {time_sent, Ts},
              {time_recv, Tr},
              {params, P}}}] ->
      add_exist_data(EtsTable, IdTuple, VTuple, {Ns, Nr, Ts, Tr, P});
    _ ->
      add_new_data(EtsTable, IdTuple, VTuple)
  end.

add_new_data(EtsTable, IdTuple, VTuple) ->
  case VTuple of
    {send, Src, TimeSend} ->
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, [Src]},
                                      {nodes_recv, []},
                                      {time_sent, [{Src, TimeSend}]},
                                      {time_recv, []},
                                      {params, []}}});

    {recv, Src, TimeRecv, RSrc, _RDst, Rssi, Integrity} ->
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, [RSrc]},
                                      {nodes_recv, [Src]},
                                      {time_sent, []},
                                      {time_recv, [{Src, RSrc, TimeRecv}]},
                                      {params, [{Src, RSrc, Rssi, Integrity}]}}})
  end.

add_exist_data(EtsTable, IdTuple, VTuple, {Ns, Nr, Ts, Tr, P}) ->
  case VTuple of
    {send, Src, TimeSend} ->
      NewNs = add_to_list(Ns, Src),
      NewTs = add_to_list(Ts, {Src, TimeSend}),
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, NewNs},
                                      {nodes_recv, Nr},
                                      {time_sent, NewTs},
                                      {time_recv, Tr},
                                      {params, P}}});

    {recv, Src, TimeRecv, RSrc, _RDst, Rssi, Integrity} ->
      NewNs = add_to_list(Ns, RSrc),
      NewNr = add_to_list(Nr, Src),
      NewTr = add_to_list(Tr, {Src, RSrc, TimeRecv}),
      NewP = add_to_list(P, {Src, RSrc, Rssi, Integrity}),
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, NewNs},
                                      {nodes_recv, NewNr},
                                      {time_sent, Ts},
                                      {time_recv, NewTr},
                                      {params, NewP}}})
  end.

add_to_list(List, Val) ->
  nl_mac_hf:check_dubl_in_path(List, Val).

bin_to_num(Bin) ->
  N = binary_to_list(Bin),
  case string:to_float(N) of
    {error, no_float} -> list_to_integer(N);
    {F, _Rest} -> F
  end.

analyse(EtsTable) ->
  io:format("!!!!!!!!!!!!!!!!!!!!! ANALYZE ~p~n", [EtsTable]),
  T = ets:match(EtsTable, '$1'),
  io:format(" ~p~n", [T]).

%log_nl_mac:start_parse(icrpr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_icrpr").
%log_nl_mac:start_parse(sncfloodr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_sncfloodr").
%log_nl_mac:start_parse(sncfloodr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_aut_lohi_sncfloodr").
