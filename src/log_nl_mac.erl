-module(log_nl_mac).

-import(lists, [filter/2, foldl/3, map/2, member/2]).
-export([start_parse/3]).

-include("nl.hrl").
-include("log.hrl").

% LogDir has to include directories for each of experiment:
%  log1, log2, log3 etc, where 1,2,3 - is local address

start_parse(MACProtocol, NLProtocol, LogDir) ->
  EtsName = list_to_atom(atom_to_list(results_) ++ atom_to_list(NLProtocol)),
  EtsTable = ets:new(EtsName, [set, named_table]),
  start_parse(EtsTable, MACProtocol, NLProtocol, LogDir, ?NODES),
  analyse(EtsTable).

start_parse(_, _, _, _, []) -> [];
start_parse(EtsTable, MACProtocol, NLProtocol, Dir, [HNode | TNodes]) ->
  LogDir = Dir ++ "/log" ++ integer_to_list(HNode),
  {ok, _} = fsm_rb:start([{report_dir, LogDir}]),
  parse_send(HNode, EtsTable, MACProtocol, NLProtocol, LogDir),
  fsm_rb:stop(),
  start_parse(EtsTable, MACProtocol, NLProtocol, Dir, TNodes).

parse_send(HNode, EtsTable, MACProtocol, NL_Protocol, LogDir) ->
  file:delete(LogDir ++ "/parse_send.log"),
  ok = fsm_rb:start_log(LogDir ++ "/parse_send.log"),
  fsm_rb:grep("MAC_AT_SEND"),
  readlines(HNode, EtsTable, MACProtocol, NL_Protocol, send, LogDir ++ "/parse_send.log"),

  file:delete(LogDir ++ "/parse_recv.log"),
  ok = fsm_rb:start_log(LogDir ++ "/parse_recv.log"),
  fsm_rb:grep("MAC_AT_RECV"),
  readlines(HNode, EtsTable, MACProtocol, NL_Protocol, recv, LogDir ++ "/parse_recv.log").

readlines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, FileName) ->
  {ok, Device} = file:open(FileName, [read]),
  try get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, "")
    after file:close(Device)
  end.

get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, OLine) ->
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
          Payl = get_payl(MACProtocol, Action, OLine),
          extract_payl(HNode, EtsTable, Action, RTuple, NL_Protocol, Time, Payl),
          get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, Line);
        nomatch ->
          get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, OLine ++ Line)
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


get_tuple(send, Line) ->
  RecvRegexp = "at,([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),.*",
  case re:run(Line, RecvRegexp, [dotall,{capture, all_but_first, binary}]) of
    {match, [_, _, _, BSrc,_]} ->
      [bin_to_num(BSrc)];
    nomatch -> nothing
  end;
get_tuple(recv, Line) ->
  RecvRegexp = "recvim,([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),(.*),.*",
  case re:run(Line, RecvRegexp, [dotall,{capture, all_but_first, binary}]) of
    {match, [_, BSrc, BDst, _, _, BRssi, BIntegrity, BVelocity]} ->
      Src = bin_to_num(BSrc),
      Dst = bin_to_num(BDst),
      Rssi = bin_to_num(BRssi),
      Integrity = bin_to_num(BIntegrity),
      Velocity = bin_to_num(BVelocity),
      [Src, Dst, Rssi, Integrity, Velocity];
    nomatch -> nothing
  end.

get_payl(aut_lohi, Action, Line) ->
  try
  case re:run(Line, "<<(.*)>>", [{capture, first, list}]) of
    {match, Match} ->
      S = re:replace(Match,"<<|>>","",[global, {return,list}]),
      LInt = lists:map(fun(X) -> {Int, _} = string:to_integer(X), Int end, string:tokens(S, ",")),
      L = lists:foldr(fun(X, A) -> <<X, A/binary>> end, <<>>, LInt),
      case Action of
        send ->
          L;
        recv ->
          [_BFlag, Data, _LenAdd] = nl_mac_hf:extract_payload_mac_flag(L),
          Data
      end;
    nomatch ->
      nothing
  end
  catch error: _Reason ->
    nothing % tones
  end;
get_payl(csma_alh, _, Line) ->
  case re:run(Line, "<<(.*)>>", [{capture, first, list}]) of
    {match, Match} ->
      S = re:replace(Match,"<<|>>","",[global, {return,list}]),
      LInt = lists:map(fun(X) -> {Int, _} = string:to_integer(X), Int end, string:tokens(S, ",")),
      lists:foldr(fun(X, A) -> <<X, A/binary>> end, <<>>, LInt);
    nomatch -> nothing
  end.

extract_payl(_, _, _, _, _, _, nothing) ->
  [];
%----------------------------------- EXTRACT SEND PAYLOAD---------------
extract_payl(HNode, EtsTable, send, STuple, icrpr, Time, Payl) ->
  [RSrc] = STuple,
  [Flag, PkgID, Src, Dst, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
  case nl_mac_hf:num2flag(Flag, nl) of
    data ->
      [Path, BData] = nl_mac_hf:extract_path_data(nothing, Data),
      add_data(EtsTable, {PkgID, BData, Src, Dst}, {send, HNode, RSrc, Time, Path});
    ack ->
      Hops = nl_mac_hf:extract_ack(nothing, Data),
      add_data(EtsTable, {PkgID, ack, Dst, Src}, {send_ack, HNode, RSrc, Time, Hops});
    dst_reached ->
      nothing;
    _ ->
      nothing
  end;
extract_payl(HNode, EtsTable, send, STuple, NLProtocol, Time, Payl) when NLProtocol =:= sncfloodr;
                                                                         NLProtocol =:= sncfloodrack;
                                                                         NLProtocol =:= dpffloodr;
                                                                         NLProtocol =:= dpffloodrack->
  [RSrc] = STuple,
  [Flag, PkgID, Src, Dst, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
  case nl_mac_hf:num2flag(Flag, nl) of
    data ->
      add_data(EtsTable, {PkgID, Data, Src, Dst}, {send, HNode, RSrc, Time});
    ack ->
      Hops = nl_mac_hf:extract_ack(nothing, Data),
      add_data(EtsTable, {PkgID, ack, Dst, Src}, {send_ack, HNode, RSrc, Time, Hops});
    dst_reached ->
      nothing;
    _ ->
      nothing
  end;
%----------------------------------- EXTRACT RECV PAYLOAD---------------
extract_payl(HNode, EtsTable, recv, RTuple, icrpr, Time, Payl) ->
  if RTuple == nothing;
     Payl == <<>> ->
    nothing;
  true ->
    [RSrc, RDst, Rssi, Integrity, Velocity] = RTuple,
    [Flag, PkgID, Src, Dst, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
    case nl_mac_hf:num2flag(Flag, nl) of
      data ->
        [Path, BData] = nl_mac_hf:extract_path_data(nothing, Data),
        add_data(EtsTable, {PkgID, BData, Src, Dst}, {recv, HNode, Time, RSrc, RDst, Rssi, Integrity, Velocity, Path});
      ack ->
        Hops = nl_mac_hf:extract_ack(nothing, Data),
        add_data(EtsTable, {PkgID, ack, Dst, Src}, {recv_ack, HNode, Time, RSrc, RDst, Hops});
      dst_reached ->
        nothing;
      _ ->
        nothing
    end
  end;
extract_payl(HNode, EtsTable, recv, RTuple, NLProtocol, Time, Payl) when NLProtocol=:= sncfloodr;
                                                                         NLProtocol =:= sncfloodrack;
                                                                         NLProtocol =:= dpffloodr;
                                                                         NLProtocol =:= dpffloodrack->
  if RTuple == nothing;
     Payl == <<>> ->
    nothing;
  true ->
    [RSrc, RDst, Rssi, Integrity, Velocity] = RTuple,
    [Flag, PkgID, Src, Dst, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
    case nl_mac_hf:num2flag(Flag, nl) of
      data ->
        add_data(EtsTable, {PkgID, Data, Src, Dst}, {recv, HNode, Time, RSrc, RDst, Rssi, Integrity, Velocity});
      ack ->
        Hops = nl_mac_hf:extract_ack(nothing, Data),
        add_data(EtsTable, {PkgID, ack, Dst, Src}, {recv_ack, HNode, Time, RSrc, RDst, Hops});
      dst_reached ->
        nothing;
      _ ->
        nothing
    end
  end.


% IdTuple = {PkgID, Data, Src, Dst}
% {send, RSrc, TimeSend}  or {send, RSrc, TimeSend, Path}
% {recv, HNode, TimeRecv, RSrc, RDst, Rssi, Integrity, Velocity}
add_data(EtsTable, IdTuple, VTuple) ->
  LookEts = ets:lookup(EtsTable, IdTuple),

  case LookEts of
    [{IdTuple, {{nodes_sent, Ns},
              {nodes_recv, Nr},
              {time_sent, Ts},
              {time_recv, Tr},
              {params, P}}}] ->
      add_exist_data(EtsTable, IdTuple, VTuple, {Ns, Nr, Ts, Tr, P});
    [{IdTuple, {{nodes_sent, Ns},
              {nodes_recv, Nr},
              {time_sent, Ts},
              {time_recv, Tr},
              {params, P},
              {paths_sent, SPaths},
              {paths_recv, RPaths} }}] ->
      add_exist_data(EtsTable, IdTuple, VTuple, {Ns, Nr, Ts, Tr, P, SPaths, RPaths});
    [{IdTuple, {{send_ack, Ns},
              {recv_ack, Nr} }}] ->
      add_exist_data(EtsTable, IdTuple, VTuple, {Ns, Nr});
    _ ->
      add_new_data(EtsTable, IdTuple, VTuple)
  end.

add_new_data(EtsTable, IdTuple, VTuple) ->
  case VTuple of
    {send_ack, Src, RSrc, TimeSend, Hops} ->
      ets:insert(EtsTable, {IdTuple, {{send_ack, [{Src, RSrc, TimeSend, Hops}]},
                                      {recv_ack, []}}});
    {recv_ack, Src, TimeRecv, RSrc, RDst, Hops} ->
      ets:insert(EtsTable, {IdTuple, {{send_ack, []},
                                      {recv_ack, [{Src, RSrc, RDst, TimeRecv, Hops}]}}});
    {send, Src, RSrc, TimeSend, Path} ->
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, [{Src, RSrc}]},
                                      {nodes_recv, []},
                                      {time_sent, [{Src, RSrc, TimeSend}]},
                                      {time_recv, []},
                                      {params, []},
                                      {paths_sent, [{Src, RSrc, Path}]},
                                      {paths_recv, []}}});
    {send, Src, RSrc, TimeSend} ->
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, [{Src, RSrc}]},
                                      {nodes_recv, []},
                                      {time_sent, [{Src, RSrc, TimeSend}]},
                                      {time_recv, []},
                                      {params, []}}});

    {recv, Src, TimeRecv, RSrc, _RDst, Rssi, Integrity, Velocity, Path} ->
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, [RSrc]},
                                      {nodes_recv, [Src]},
                                      {time_sent, []},
                                      {time_recv, [{Src, RSrc, TimeRecv}]},
                                      {params, [{Src, RSrc, Rssi, Integrity, Velocity}]},
                                      {paths_sent, []},
                                      {paths_recv, [{Src, RSrc, Path}]} }});

    {recv, Src, TimeRecv, RSrc, _RDst, Rssi, Integrity, Velocity} ->
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, [RSrc]},
                                      {nodes_recv, [Src]},
                                      {time_sent, []},
                                      {time_recv, [{Src, RSrc, TimeRecv}]},
                                      {params, [{Src, RSrc, Rssi, Integrity, Velocity}]}}})
  end.

add_exist_data(EtsTable, IdTuple, VTuple, {Ns, Nr}) ->
  case VTuple of
    {send_ack, Src, RSrc, TimeSend, Hops} ->
      NewNs = add_to_list(Ns, {Src, RSrc, TimeSend, Hops}),
      ets:insert(EtsTable, {IdTuple, {{send_ack, NewNs},
                                      {recv_ack, Nr}}});

    {recv_ack, Src, TimeRecv, RSrc, RDst, Hops} ->
      NewNr = add_to_list(Nr, {Src, RSrc, RDst, TimeRecv, Hops}),
      ets:insert(EtsTable, {IdTuple, {{send_ack, Ns},
                                      {recv_ack, NewNr}}})
  end;
add_exist_data(EtsTable, IdTuple, VTuple, {Ns, Nr, Ts, Tr, P, SPaths, RPaths}) ->
  case VTuple of
    {send, Src, RSrc, TimeSend, Path} ->
      NewNs = add_to_list(Ns, {Src, RSrc}),
      NewTs = add_to_list(Ts, {Src, RSrc, TimeSend}),
      NewSPath = add_to_list(SPaths, {Src, RSrc, Path}),
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, NewNs},
                                      {nodes_recv, Nr},
                                      {time_sent, NewTs},
                                      {time_recv, Tr},
                                      {params, P},
                                      {paths_sent, NewSPath},
                                      {paths_recv, RPaths} }});
    {recv, Src, TimeRecv, RSrc, _RDst, Rssi, Integrity, Velocity, Path} ->
      NewNr = add_to_list(Nr, Src),
      NewTr = add_to_list(Tr, {Src, RSrc, TimeRecv}),
      NewP = add_to_list(P, {Src, RSrc, Rssi, Integrity, Velocity}),
      NewRPath = add_to_list(RPaths, {Src, RSrc, Path}),
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, Ns},
                                      {nodes_recv, NewNr},
                                      {time_sent, Ts},
                                      {time_recv, NewTr},
                                      {params, NewP},
                                      {paths_sent, SPaths},
                                      {paths_recv, NewRPath} }})
  end;
add_exist_data(EtsTable, IdTuple, VTuple, {Ns, Nr, Ts, Tr, P}) ->
  case VTuple of
    {send, Src, RSrc, TimeSend} ->
      NewNs = add_to_list(Ns, {Src, RSrc}),
      NewTs = add_to_list(Ts, {Src, RSrc, TimeSend}),
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, NewNs},
                                      {nodes_recv, Nr},
                                      {time_sent, NewTs},
                                      {time_recv, Tr},
                                      {params, P}}});

    {recv, Src, TimeRecv, RSrc, _RDst, Rssi, Integrity, Velocity} ->
      NewNr = add_to_list(Nr, Src),
      NewTr = add_to_list(Tr, {Src, RSrc, TimeRecv}),
      NewP = add_to_list(P, {Src, RSrc, Rssi, Integrity, Velocity}),
      ets:insert(EtsTable, {IdTuple, {{nodes_sent, Ns},
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

cat_data_ack(EtsTable) ->
  [List_all_data, List_all_acks] =
  ets:foldl(
    fun(X, [L1, L2]) ->
      case X of
        {{_PkgID, ack, _Src, _Dst}, _} ->
          [L1, [X | L2]];

        {{_PkgID, _Data, _Src, _Dst}, _} ->
          [[X | L1], L2]
      end
    end
  , [ [], [] ], EtsTable),

  case List_all_acks of
    [] -> List_all_data;
    _ ->
      lists:foldl(
        fun(X, A) ->
          [add_ack_to_data(X, List_all_data) | A]
        end
      , [], List_all_acks)
  end.

add_ack_to_data({{PkgID, ack, Src, Dst}, StatAck}, List_all_data) ->
  lists:foldl(
    fun(X, A) ->
      case X of
        {{PkgID, Data, Src, Dst}, StatData} ->
          Res = {{PkgID, Data, Src, Dst}, {StatData,  {ack, StatAck} } },
          [Res | A];
        _ ->
          A
      end
    end
  , [], List_all_data).

  analyse(EtsTable) ->
  Res = cat_data_ack(EtsTable),
  io:format(" ~p~n", [Res]).


%log_nl_mac:start_parse(csma_alh, icrpr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_icrpr").
%log_nl_mac:start_parse(csma_alh, sncfloodr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_sncfloodr").
%log_nl_mac:start_parse(csma_alh, sncfloodrack, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_sncfloodrack").
%log_nl_mac:start_parse(csma_alh, dpffloodr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_dpffloodr").
%log_nl_mac:start_parse(csma_alh, dpffloodrack, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_dpffloodrack").

%log_nl_mac:start_parse(aut_lohi, sncfloodr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_aut_lohi_sncfloodr").
