-module(log_nl_mac).

-import(lists, [filter/2, foldl/3, map/2, member/2]).
-export([start_parse/3, sync_time/3]).

-include("nl.hrl").
-include("log.hrl").

% LogDir has to include directories for each of experiment:
%  log1, log2, log3 etc, where 1,2,3 - is local address

start_parse(MACProtocol, NLProtocol, LogDir) ->
  EtsName = list_to_atom(atom_to_list(results_) ++ atom_to_list(NLProtocol)),
  EtsTable = ets:new(EtsName, [set, named_table]),
  ets:insert(EtsTable, {path, LogDir}),
  start_parse(EtsTable, MACProtocol, NLProtocol, LogDir, ?NODES),
  analyse(EtsTable, NLProtocol).

start_parse(_, _, _, _, []) -> [];
start_parse(EtsTable, MACProtocol, NLProtocol, Dir, [HNode | TNodes]) ->
  LogDir = Dir ++ "/log" ++ integer_to_list(HNode),
  {ok, _} = fsm_rb:start([{report_dir, LogDir}]),
  parse_send(HNode, EtsTable, MACProtocol, NLProtocol, LogDir),
  fsm_rb:stop(),
  start_parse(EtsTable, MACProtocol, NLProtocol, Dir, TNodes).

parse_send(HNode, EtsTable, MACProtocol, NL_Protocol, LogDir) ->
  file:delete(LogDir ++ "/parse_intervals.log"),
  ok = fsm_rb:start_log(LogDir ++ "/parse_intervals.log"),
  fsm_rb:grep("XXXXXXXXXXXXXXXXXXXXXX"),
  readlines(HNode, EtsTable, MACProtocol, NL_Protocol, intervals, LogDir ++ "/parse_intervals.log"),

  SourecAdd = (HNode == 7) and ((NL_Protocol == sncfloodrack) or (NL_Protocol == dpffloodrack)),
  if SourecAdd ->
    readlines(HNode, EtsTable, MACProtocol, NL_Protocol, source_data, LogDir ++ "/parse_intervals.log");
  true -> nothing
  end,

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
        source_data -> "Source";
        intervals -> "handle_event";
        send -> "MAC_AT_SEND";
        recv -> "MAC_AT_RECV"
      end,
      {ok, TimeReg} = re:compile("(.*)[0-9]+\.[0-9]+\.[0-9]+(.*)" ++ ActionStr),
      case re:run(Line, TimeReg, []) of
        {match, _Match} ->
          case Action of
            intervals ->
              Time = get_time(Line),
              Interval = get_payl(MACProtocol, Action, Line),

              Res = ets:lookup(EtsTable, {interval, HNode, Interval}),
              case Res of
                [{_, Timestamp}] ->
                  ets:insert(EtsTable, {{interval, HNode, Interval}, [Time | Timestamp] });
                _ ->
                  ets:insert(EtsTable, {{interval, HNode, Interval}, [Time] })
              end,
              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, Line);
            _ ->
              Time = get_time(OLine),
              RTuple = get_tuple(Action, OLine),
              Payl = get_payl(MACProtocol, Action, OLine),
              extract_payl(HNode, EtsTable, Action, RTuple, NL_Protocol, Time, Payl),
              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, Line)
            end;
        nomatch ->
          case Action of
            intervals ->
              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, Line);
            source_data ->
              case re:run(Line, "(.*)Source Data:(.*) Len:(.*)State:(.*) Total:(.*)Hops:([0-9]+)(.*)>>", [dotall,{capture, all_but_first, binary}]) of
                {match, [_, M, _, S, _, H, _]} ->
                  ets:insert(EtsTable, {{source_data, M}, {S, bin_to_num(H) } });
                nomatch ->
                  nothing
              end,
              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, Line);
            _ ->
              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, OLine ++ Line)
          end
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

get_payl(_, intervals, Line) ->
  case re:run(Line, "(.*)([^:][0-9]+):XXXXXXXXXXXXXXXXXXXXXX", [dotall,{capture, all_but_first, binary}]) of
    {match,[_, Interval]} ->
      I = re:replace(Interval, "[^0-9]", "", [global, {return, list}]),
      bin_to_num(list_to_binary(I));
    nomatch ->
      nothing
  end;
get_payl(csma_alh, _, Line) ->
  case re:run(Line, "<<(.*)>>", [dotall,{capture, all_but_first, binary}]) of
    {match, Match} ->
      T = re:replace(Match,"<<|>>|\n","",[global, {return,list}]),
      S = re:replace(T," ","",[global, {return,list}]),
      LInt = lists:map(fun(X) -> {Int, _} = string:to_integer(X), Int end, string:tokens(S, ",")),
      lists:foldr(fun(X, A) -> <<X, A/binary>> end, <<>>, LInt);
    nomatch -> nothing
  end;
get_payl(_, Action, Line) ->
  try
  case re:run(Line, "<<(.*)>>", [dotall,{capture, all_but_first, binary}]) of
    {match, Match} ->
      T = re:replace(Match,"<<|>>|\n","",[global, {return,list}]),
      S = re:replace(T," ","",[global, {return,list}]),
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
          [[X | L1], L2];
        _ ->
          [L1, L2]
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


sync_time(Table, NLProtocol, EtsTable) ->
  sync_time(Table, [], NLProtocol, EtsTable).

sync_time([], SyncTable, _, _) ->
  SyncTable;
sync_time([Pkg | T], SyncTable, NLProtocol, EtsTable) ->
  SyncPkg = sync_pkg(Pkg, NLProtocol, EtsTable),
  sync_time(T, [SyncPkg | SyncTable], NLProtocol, EtsTable).

sync_pkg(Pkg, NLProtocol, EtsTable) ->
  case NLProtocol of
    icrpr ->
      [{ IdTuple, {RelayTuple, AckTuple}}] = Pkg,
      {_PkgId, _Data, Src, _Dst} = IdTuple,

      {{nodes_sent, NS},
      {nodes_recv, NR},
      {time_sent, LNSent},
      {time_recv, LNRecv},
      {params, Params},
      {paths_sent, SPath},
      {paths_recv, RPath}} = RelayTuple,

      {ack, {
      {send_ack, _SendAck},
      {recv_ack, _RecvAck}}} = AckTuple,

      ets:insert(EtsTable, {sync_neighbours, [Src]}),
      [NewLNSent, NewLNRecv] = start_sync_neighbour([Src], LNSent, LNRecv, EtsTable),

      SyncRelayTuple = {{nodes_sent, NS},
      {nodes_recv, NR},
      {time_sent, NewLNSent},
      {time_recv, NewLNRecv},
      {params, Params},
      {paths_sent, SPath},
      {paths_recv, RPath}},

      %TODO SYnc Ack tuple
      [{ IdTuple, {SyncRelayTuple, AckTuple}}];
    _ when NLProtocol =:= sncfloodrack;
           NLProtocol =:= dpffloodrack ->

       [{ IdTuple, {RelayTuple, AckTuple}}] = Pkg,
      {_PkgId, _Data, Src, _Dst} = IdTuple,

      {{nodes_sent, NS},
      {nodes_recv, NR},
      {time_sent, LNSent},
      {time_recv, LNRecv},
      {params, Params}} = RelayTuple,

      {ack, {
      {send_ack, _SendAck},
      {recv_ack, _RecvAck}}} = AckTuple,

      ets:insert(EtsTable, {sync_neighbours, [Src]}),
      [NewLNSent, NewLNRecv] = start_sync_neighbour([Src], LNSent, LNRecv, EtsTable),

      SyncRelayTuple = {{nodes_sent, NS},
      {nodes_recv, NR},
      {time_sent, NewLNSent},
      {time_recv, NewLNRecv},
      {params, Params}},

      %TODO SYnc Ack tuple
      [{ IdTuple, {SyncRelayTuple, AckTuple}}];

    _ ->
      {IdTuple, RelayTuple} = Pkg,
      {_PkgId, _Data, Src, _Dst} = IdTuple,

      {{nodes_sent, NS},
      {nodes_recv, NR},
      {time_sent, LNSent},
      {time_recv, LNRecv},
      {params, Params}} = RelayTuple,

      ets:insert(EtsTable, {sync_neighbours, [Src]}),
      [NewLNSent, NewLNRecv] = start_sync_neighbour([Src], LNSent, LNRecv, EtsTable),

      SyncRelayTuple = {{nodes_sent, NS},
      {nodes_recv, NR},
      {time_sent, NewLNSent},
      {time_recv, NewLNRecv},
      {params, Params}},

      %TODO SYnc Ack tuple
      { IdTuple, SyncRelayTuple}
  end.


start_sync_neighbour(0, LNSent, LNRecv, _) ->
  [LNSent, LNRecv];
start_sync_neighbour(Src, LNSent, LNRecv, EtsTable) ->
 [NotSyncNeighbours, NewLNSent, NewLNRecv] = sync_neighbour_helper(Src, LNSent, LNRecv, EtsTable, []),
  case NotSyncNeighbours of
    [] ->
      start_sync_neighbour(0, NewLNSent, NewLNRecv, EtsTable);
    _ ->
      start_sync_neighbour(NotSyncNeighbours, NewLNSent, NewLNRecv, EtsTable)
  end.

sync_neighbour_helper([], NewLNSent, NewLNRecv, _, Neighbours) ->
  CNeighbours = lists:flatten(Neighbours),
  [CNeighbours, NewLNSent, NewLNRecv];
sync_neighbour_helper([Src | T], LNSent, LNRecv, EtsTable, Neighbours) ->
  [{sync_neighbours, Sync_list}] = ets:lookup(EtsTable, sync_neighbours),
  [SyncNeighbours, NewLNSent, NewLNRecv] = sync_neighbour(Src, LNSent, LNRecv, EtsTable),

  CNeighbours = lists:foldr(fun(X, A) ->
      case lists:member(X, Sync_list) of
        true -> A;
        _ -> [X, A]
      end
    end, [], SyncNeighbours),

  case lists:member(Src, Sync_list) of
    true ->
      sync_neighbour_helper(T, NewLNSent, NewLNRecv, EtsTable, [CNeighbours | Neighbours]);
    _ ->
      Sync_list_new = add_to_list(Sync_list, Src),
      ets:insert(EtsTable, {sync_neighbours, Sync_list_new}),
      sync_neighbour_helper(T, NewLNSent, NewLNRecv, EtsTable, [CNeighbours | Neighbours])
  end.

sync_neighbour(Src, LNSent, LNRecv, EtsTable) ->
  TimeSent = lists:foldr(fun(X, A) -> case X of {Src, _, _} -> [X | A]; _ -> A end end, [], LNSent),
  [NeighboursRecv, NotNeighboursRecv] =
  lists:foldr(
    fun(X, [A, NA]) ->
      case X of
        {_, Src, _} -> [[X | A], NA];
        _ -> [A, [X | NA]]
      end
    end, [[], []], LNRecv),

  % TODO: if more than 1 retry
  [SyncNeighboursRecv, Neighbours] =
  case length(TimeSent) of
    0 -> [[], []];
    1 ->
      [{_, _, STimeStamp}] = TimeSent,
      lists:foldr( fun(X, [A, ADst]) ->
        {Dst, RDst, RTimeStamp} = X,
        NewTimeStamp = find_delta_t(Src, STimeStamp, Dst, RTimeStamp, EtsTable),
        [[{Dst, RDst, NewTimeStamp} | A], [Dst | ADst]]
      end, [[], []], NeighboursRecv);
    _ ->
      {_, _, STimeStamp} = lists:last(TimeSent),
      lists:foldr( fun(X, [A, ADst]) ->
        {Dst, RDst, RTimeStamp} = X,
        NewTimeStamp = find_delta_t(Src, STimeStamp, Dst, RTimeStamp, EtsTable),
        [[{Dst, RDst, NewTimeStamp} | A], [Dst | ADst]]
      end, [[], []], NeighboursRecv)
  end,

  [SyncNeighboursSent, NotNeighboursSend]=
  lists:foldr(
    fun(X, [A, SNA]) ->
      Res =
      lists:foldr(
        fun(NSrc, NA) ->
          case X of
            {NSrc, Dst, SendTimeStamp} ->
              NewTimeStamp = find_delta_t(Src, SendTimeStamp, NSrc, EtsTable),
              [{NSrc, Dst, NewTimeStamp} | NA];
            _ ->
            NA
          end
        end, [], Neighbours),
      if Res == [] ->
        [A, [X |SNA]];
      true ->
        [[Res | A], SNA]
      end
    end, [[], []], LNSent),

  NewSendList = lists:flatten(lists:merge([SyncNeighboursSent, NotNeighboursSend])),
  NewRecvList = lists:merge(SyncNeighboursRecv, NotNeighboursRecv),

  [Neighbours, NewSendList, NewRecvList].

find_delta_t(NSrc, STimeStamp, Dst, EtsTable) ->
  case is_float(STimeStamp) of
    true ->
      STimeStamp;
    _ ->
      case ets:lookup(EtsTable, {NSrc, Dst}) of
        [{{NSrc, Dst}, Delta}] ->
          STimeStamp + Delta;
        _     ->
          STimeStamp
      end
  end.

find_delta_t(Src, STimeStamp, Dst, RTimeStamp, EtsTable) ->
  case is_float(RTimeStamp) of
    true ->
      RTimeStamp;
    _ ->
      Dist = distance(Src, Dst),
      TransmissionTime = (Dist / ?SOUND_SPEED)  * 1000000,
      Delta = STimeStamp - RTimeStamp + TransmissionTime,
      ets:insert(EtsTable, { {Src, Dst}, Delta}),
      RTimeStamp + Delta
  end.

distance(P1, P2) ->
  {Lt1, Lg1} = ?POSITION(P1),
  {Lt2, Lg2} = ?POSITION(P2),
  calc_distance(Lg1, Lt1, Lg2, Lt2).

calc_distance(Lng1, Lat1, Lng2, Lat2) ->
  Deg2rad = fun(Deg) -> math:pi() * Deg/180 end,
  [RLng1, RLat1, RLng2, RLat2] = [Deg2rad(Deg) || Deg <- [Lng1, Lat1, Lng2, Lat2]],

  DLon = RLng2 - RLng1,
  DLat = RLat2 - RLat1,

  A = math:pow(math:sin(DLat/2), 2) + math:cos(RLat1) * math:cos(RLat2) * math:pow(math:sin(DLon/2), 2),

  C = 2 * math:asin(math:sqrt(A)),
  Km = 6372.8 * C,
  Km * 1000.

get_time_sent_interval(NLProtocol, Src, Pkg, Action) ->
  case NLProtocol of
    icrpr ->
      [{ IdTuple, {RelayTuple, AckTuple}}] = Pkg,
      {PkgId, Data, Src, _Dst} = IdTuple,
      {{nodes_sent, _NS},
      {nodes_recv, _NR},
      {time_sent, LNSent},
      {time_recv, _LNRecv},
      {params, _Params},
      {paths_sent, _SPath},
      {paths_recv, _RPath}} = RelayTuple,

      {ack, {
      {send_ack, _SendAck},
      {recv_ack, _RecvAck}}} = AckTuple,

      case Action of
        send_time ->
          lists:foldr(fun(X, A) -> case X of {Src, _, Time} -> Time; _ -> A end end, 0, LNSent);
        send_pkg ->
          PkgId;
        send_data ->
          Data
      end;
    _ when NLProtocol =:= sncfloodrack;
           NLProtocol =:= dpffloodrack ->
      [{ IdTuple, {RelayTuple, AckTuple}}] = Pkg,
      {PkgId, Data, Src, _Dst} = IdTuple,
      LNSent =
      case RelayTuple of
        {{nodes_sent, _NS},
        {nodes_recv, _NR},
        {time_sent, LNSentTmp},
        {time_recv, _LNRecv},
        {params, _Params},
        {stats, _Stats}} -> LNSentTmp;
        {{nodes_sent, _NS},
        {nodes_recv, _NR},
        {time_sent, LNSentTmp},
        {time_recv, _LNRecv},
        {params, _Params}} -> LNSentTmp
      end,

      {ack, {
      {send_ack, _SendAck},
      {recv_ack, _RecvAck}}} = AckTuple,
      case Action of
        send_time ->
          lists:foldr(fun(X, A) -> case X of {Src, _, Time} -> Time; _ -> A end end, 0, LNSent);
        send_pkg ->
          PkgId;
        send_data ->
          Data
      end;
    _ ->
      {IdTuple, RelayTuple} = Pkg,
      {PkgId, Data, Src, _Dst} = IdTuple,
      {{nodes_sent, _NS},
      {nodes_recv, _NR},
      {time_sent, LNSent},
      {time_recv, _LNRecv},
      {params, _Params}} = RelayTuple,
      case Action of
        send_time ->
          lists:foldr(fun(X, A) -> case X of {Src, _, Time} -> Time; _ -> A end end, 0, LNSent);
        send_pkg ->
          PkgId;
        send_data ->
          Data
      end
  end.

%TODO: Src not to sync!!!!


find_pkg_interval(Table, NLProtocol) ->
  lists:foldr( fun(X, Acc) ->
    case X of
      {{_Pkg, Msg, Src, _Dst}, _} ->
        case re:run(Msg, "([^:]*):XXXXXXXXXXXXXXXXXXXXXX", [dotall,{capture, all_but_first, binary}]) of
          {match,[Interval]} ->
            NS = get_time_sent_interval(NLProtocol, Src, X, send_pkg),
            Res = lists:foldr(fun(XX, A) -> case XX of {Interval, _} -> true; _ -> A end end, false, Acc),
            if Res =:= true ->
              Acc;
            true ->
              [ {Interval, NS} | Acc]
            end;
          nomatch ->
            Acc
        end;
      [{{_Pkg, Msg, Src, _Dst}, _}] ->
        case re:run(Msg, "([^:]*):XXXXXXXXXXXXXXXXXXXXXX", [dotall,{capture, all_but_first, binary}]) of
          {match,[Interval]} ->
            NS = get_time_sent_interval(NLProtocol, Src, X, send_pkg),
            Res = lists:foldr(fun(XX, A) -> case XX of {Interval, _} -> true; _ -> A end end, false, Acc),
            if Res =:= true ->
              Acc;
            true ->
              [ {Interval, NS} | Acc]
            end;
          nomatch ->
            Acc
        end;
      _ ->
        Acc
    end
  end, [], Table).

find_timestamp_pkgid(Table, PkgId) ->
  {DT, _} =
  lists:foldr(
  fun(_X, {D, A}) ->
    if D ==  nothing ->
      case find_timestamp_pkgid_helper(Table, A) of
        nothing -> {nothing, A + 1};
        Data -> {Data, A}
      end;
    true ->
      {D, A}
    end
  end, {nothing, PkgId + 1}, Table),
  DT.

find_timestamp_pkgid_helper(Table, PkgId) ->
  lists:foldr(
  fun(X, A) ->
    if A =/= nothing -> A;
    true ->
      case X of
        {{PkgId, Msg, _Src, _Dst}, _} ->
          Msg;
        [{{PkgId, Msg, _Src, _Dst}, _}] ->
          Msg;
        _ ->
          nothing
      end
    end
  end, nothing, Table).

prepare_add_info(EtsTable, Table, NLProtocol) ->
  NTable =
  lists:foldr( fun(X, Acc) ->
    case X of
      {Id = {_Pkg, Msg, Src, _Dst}, RelayTuple} ->
        case re:run(Msg, "([^:]*):XXXXXXXXXXXXXXXXXXXXXX", [dotall,{capture, all_but_first, binary}]) of
          nomatch ->
            NSent = get_time_sent_interval(NLProtocol, Src, X, send_time),
            if(NSent =:= 0) ->
              LMsg = binary_to_list(Msg),
              LTStapms = lists:last(string:tokens(LMsg, ",")),
              TStapms = list_to_integer(LTStapms) * 1000000,
              {{nodes_sent, NS},
              {nodes_recv, NR},
              {time_sent, LNSent},
              {time_recv, LNRecv},
              {params, Params}} = RelayTuple,
              NNS = add_to_list(NS, {Src, 255}),
              NLNSent = add_to_list(LNSent, {Src, 255, TStapms}),
              NRelayTuple = {{nodes_sent, NNS},
              {nodes_recv, NR},
              {time_sent, NLNSent},
              {time_recv, LNRecv},
              {params, Params}},
              [{Id, NRelayTuple} | Acc];
            true ->
              [X | Acc]
            end;
          {match, _} ->
            [X | Acc]
        end;
      [{Id = {_Pkg, Msg, Src, _Dst}, {RelayTuple, AckTuple}}] when NLProtocol =:= icrpr ->
        case re:run(Msg, "([^:]*):XXXXXXXXXXXXXXXXXXXXXX", [dotall,{capture, all_but_first, binary}]) of
          nomatch ->
            NSent = get_time_sent_interval(NLProtocol, Src, X, send_time),
            if(NSent =:= 0) ->
              LMsg = binary_to_list(Msg),
              LTStapms = lists:last(string:tokens(LMsg, ",")),
              TStapms = list_to_integer(LTStapms) * 1000000,
              {{nodes_sent, NS},
              {nodes_recv, NR},
              {time_sent, LNSent},
              {time_recv, LNRecv},
              {params, Params},
              {paths_sent, SPath},
              {paths_recv, RPath}} = RelayTuple,
              NNS = add_to_list(NS, {Src, 255}),
              NLNSent = add_to_list(LNSent, {Src, 255, TStapms}),
              NRelayTuple = {{nodes_sent, NNS},
              {nodes_recv, NR},
              {time_sent, NLNSent},
              {time_recv, LNRecv},
              {params, Params},
              {paths_sent, SPath},
              {paths_recv, RPath}},
              [ [{Id, {NRelayTuple, AckTuple} }] | Acc];
            true ->
              [X | Acc]
            end;
        {match, _} ->
            [X | Acc]
        end;
      [{Id = {_Pkg, Msg, Src, _Dst}, {RelayTuple, AckTuple}}] ->
        { State, Hops} =
        case ets:lookup(EtsTable, {source_data, Msg}) of
          [{{source_data, Msg}, {S, H}}] ->
            {S, H};
          _->
            {nothing, nothing}
        end,

        case re:run(Msg, "([^:]*):XXXXXXXXXXXXXXXXXXXXXX", [dotall,{capture, all_but_first, binary}]) of
          nomatch ->
            NSent = get_time_sent_interval(NLProtocol, Src, X, send_time),
            if(NSent =:= 0) ->
              LMsg = binary_to_list(Msg),
              LTStapms = lists:last(string:tokens(LMsg, ",")),
              TStapms = list_to_integer(LTStapms) * 1000000,
              {{nodes_sent, NS},
              {nodes_recv, NR},
              {time_sent, LNSent},
              {time_recv, LNRecv},
              {params, Params}} = RelayTuple,
              NNS = add_to_list(NS, {Src, 255}),
              NLNSent = add_to_list(LNSent, {Src, 255, TStapms}),
              NRelayTuple = {{nodes_sent, NNS},
              {nodes_recv, NR},
              {time_sent, NLNSent},
              {time_recv, LNRecv},
              {params, Params},
              {stats, { State, Hops}}},
              [ [{Id, {NRelayTuple, AckTuple }}] | Acc];
            true ->
              [X | Acc]
            end;
        {match, _} ->
            [X | Acc]
        end;
      _ ->
        Acc
    end
  end, [], Table),

  NTable.

analyse(EtsTable, NLProtocol) ->
  Table = cat_data_ack(EtsTable),
  AddTable = prepare_add_info(EtsTable, Table, NLProtocol),

  Is = [4, 8, 15],

  OIntervals =
  lists:foldr(fun(X, A) ->
    Res = ets:lookup(EtsTable, {interval, 7, X}),
    case Res of
      [{_, Timestamp}] ->
        [{X, Timestamp} | A];
      _ -> A
    end
  end, [], Is),

  TIntervals =
  if(length(OIntervals) < 3) ->
    PkgIds = find_pkg_interval(AddTable, NLProtocol),
    AddIntervals =
    lists:foldr( fun(X, A) ->
      {Intv, PkgId} = X,
      TimeNextPkgId = find_timestamp_pkgid(AddTable, PkgId),
      LTimeNextPkgId = binary_to_list(TimeNextPkgId),
      LTStapms = lists:last(string:tokens(LTimeNextPkgId, ",")),
      TStapms = list_to_integer(LTStapms) * 1000000,
      [ {bin_to_num(Intv), [TStapms]} | A]
    end , [], PkgIds),

    io:format("------------> ~p~n", [AddIntervals]),
    AddIntervals;
  true ->
    OIntervals
  end,

  Intervals =
  if(length(TIntervals) =:= 1) ->
    [{_, [FirstTmsp]}] = TIntervals,
    MinTimeStamp =
    lists:foldr( fun(X, Min) ->
      case X of
        {{_Pkg, _Msg, Src, _Dst}, _} ->
          NS = get_time_sent_interval(NLProtocol, Src, X, send_time),
          NSVal = (NS < Min) and (NS > 0),
          if NSVal -> NS;
          true -> Min
          end;
        [{{_Pkg, _Msg, Src, _Dst}, _}] ->
          NS = get_time_sent_interval(NLProtocol, Src, X, send_time),
          NSVal = (NS < Min) and (NS > 0),
          if NSVal -> NS;
          true -> Min
          end;
        _ -> Min
      end
    end, 1000000000000, AddTable),
    TT = [{15, [MinTimeStamp]} | TIntervals],
    [{4, [FirstTmsp + 800000000]} | TT];
  true ->
    TIntervals
  end,

  TableIntervals =
  lists:foldr( fun(X, Acc) ->
    case X of
      {{_Pkg, _Msg, Src, _Dst}, _} ->
        NS = get_time_sent_interval(NLProtocol, Src, X, send_time),
        I = find_interval(NS, lists:reverse(Intervals), Is),
        [{I, X} | Acc];
      [{{_Pkg, _Msg, Src, _Dst}, _}] ->
        NS = get_time_sent_interval(NLProtocol, Src, X, send_time),
        I = find_interval(NS, lists:reverse(Intervals), Is),
        [{I, X} | Acc];
      _ ->
        Acc
    end
  end, [], AddTable),


  CountIntPkg =
  lists:foldr( fun(X, {N1, N2, N3}) ->
    {Int, _} = X,
    case Int of
      4 -> {N1 + 1, N2, N3};
      8 -> {N1, N2 + 1, N3};
      15 -> {N1, N2, N3 + 1};
      _ -> {N1, N2, N3}
    end
  end, {0, 0, 0}, TableIntervals),

  %EtsSyncTable = ets:new(sync_links, [set, named_table]),
  %SyncTable = sync_time(Table, NLProtocol, EtsSyncTable),

  [{path, Dir}] = ets:lookup(EtsTable, path),
  file:delete(Dir ++ "/res.log"),
  file:write_file(Dir ++ "/res.log", io_lib:fwrite("~p ~n", [TableIntervals])),

  io:format(" ~p~n", [CountIntPkg]),
  io:format(" ~p~n", [Intervals]).

find_interval(NS, Intervals, Is) ->
  { LIntervals, L, _Tmp } =
  lists:foldr(
    fun(_X, {Intvs, A, I}) ->
      T = lists:nth(I, Intervals),
      {Intv, _} = T,
      { [Intv | Intvs], [T | A], I + 1 }
    end, {[], [], 1}, Intervals),

  Default =
  if(length(Intervals) < 3) ->
    lists:foldr(fun(X, A) ->
    if (A == -1) ->
      Member =  lists:member(X, LIntervals),
      if Member -> -1;
        true -> X
      end;
      true -> A
      end
    end, -1, Is);
  true -> 15
  end,

  find_interval_helper(NS, L, 0, Default).

find_interval_helper(_, [], NI, _) -> NI;
find_interval_helper(_, [{_, []}, {_, []}, {_, []}], NI, _) -> NI;
find_interval_helper(NS, L, NI, Default) ->
  {IMax, TMax} = lists:foldr(
    fun(X, {CI, A})->
      {I, T} = X,
      if T == [] ->
        {CI, A};
      true ->
        CM = lists:max(T),
        if(CM > A) -> {I, CM};
          true -> {CI, A}
        end
      end
      end, {nothing, -1}, L),

  case {IMax, TMax} of
    {nothing, -1} ->
      io:format("!!!!!!!!!!!!!!!! ~p~n", [Default]),
      find_interval_helper(NS, [], Default, Default);
    _ ->
      NL = lists:foldr(fun(X, A)-> {I, T} = X, Member = lists:member(TMax, T), if Member -> NT = lists:delete(TMax, T), [ {I, NT}| A]; true -> [X | A] end end, [], L),

      if NS < TMax ->
        find_interval_helper(NS, NL, NI, Default);
      true ->
        find_interval_helper(NS, [], IMax, Default)
      end
  end.

%log_nl_mac:start_parse(csma_alh, icrpr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_icrpr").
%log_nl_mac:start_parse(csma_alh, sncfloodr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_sncfloodr").
%log_nl_mac:start_parse(csma_alh, sncfloodrack, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_sncfloodrack").
%log_nl_mac:start_parse(csma_alh, dpffloodr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_dpffloodr").
%log_nl_mac:start_parse(csma_alh, dpffloodrack, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_alh_dpffloodrack").

%log_nl_mac:start_parse(aut_lohi, sncfloodr, "/home/nikolya/work/experiments/prepare_sahalinsk/sea_tests/evins_nl_mac_27.01.2016/test_aut_lohi_sncfloodr").
