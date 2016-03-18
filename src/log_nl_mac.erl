-module(log_nl_mac).

-import(lists, [filter/2, foldl/3, map/2, member/2]).
-export([start_parse/3, sync_time/4, distance/2, start_sync/6]).

-include("nl.hrl").
-include("log.hrl").

% LogDir has to include directories for each of experiment:
%  log1, log2, log3 etc, where 1,2,3 - is local address

start_parse(MACProtocol, NLProtocol, LogDir) ->
  EtsName = list_to_atom(atom_to_list(results_) ++ atom_to_list(NLProtocol)),
  EtsTable = ets:new(EtsName, [set, named_table]),
  ets:insert(EtsTable, {path, LogDir}),
  start_parse(EtsTable, MACProtocol, NLProtocol, LogDir, ?NODES),
  analyse(EtsTable, MACProtocol, NLProtocol).

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

  SourecAdd = (HNode == ?SRC) and ((NL_Protocol == sncfloodrack) or (NL_Protocol == dpffloodrack) or (NL_Protocol == icrpr)),
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
  readlines(HNode, EtsTable, MACProtocol, NL_Protocol, recv, LogDir ++ "/parse_recv.log"),

  file:delete(LogDir ++ "/multipath.log"),
  ok = fsm_rb:start_log(LogDir ++ "/multipath.log"),
  fsm_rb:grep("MAC_AT_RECV"),
  fsm_rb:grep("Multipath"),
  readlines(HNode, EtsTable, MACProtocol, NL_Protocol, multipath, LogDir ++ "/multipath.log").

readlines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, FileName) ->
  {ok, Device} = file:open(FileName, [read]),
  try get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, "", [])
    after file:close(Device)
  end.

ckeck_pkg_multipath(HNode, TAddList, TimeP, Mult) ->
  {_, FromAddr, ResM} = Mult,
  {_D, ResCheck} =
  lists:foldr(
  fun(X, {MinTime, TRres}) ->
    case X of
      {TimeT, {Flag, PkgID, FromAddr, _RDst, Data}} ->
        DiffT = TimeP - TimeT,
        if (DiffT > 0) ->
          if (MinTime == 0) ->
            {DiffT, {Flag, PkgID, HNode, FromAddr, Data, ResM}};
          true ->
            if DiffT < MinTime ->
              {DiffT, {Flag, PkgID, HNode, FromAddr, Data, ResM}};
            true ->
              {MinTime, TRres}
            end
          end;
        true ->
          {MinTime, TRres}
        end;
      _ ->
        {MinTime, TRres}
    end
  end,
  {0, 0}, TAddList),
  ResCheck.

get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, OLine, AddList) ->
  case io:get_line(Device, "") of
    eof  -> [];
    Line ->
      ActionStr =
      case Action of
        multipath -> "(Multipath|MAC_AT_RECV)";
        source_data -> "Source";
        intervals -> "handle_event";
        send -> "MAC_AT_SEND";
        recv -> "MAC_AT_RECV"
      end,
      {ok, TimeReg} = re:compile("(.*)[0-9]+\.[0-9]+\.[0-9]+(.*)" ++ ActionStr),
      case re:run(Line, TimeReg, []) of
        {match, _Match} ->
          case Action of
            multipath ->
              Payl = get_payl(MACProtocol, recv, OLine),
              TAddList =
              if Payl =/= nothing ->
                 TimeP = get_time(OLine),
                 RTuple = get_tuple(recv, OLine),
                 ETuple = extract_payl(HNode, EtsTable, recv, RTuple, NL_Protocol, TimeP, Payl, noadd),
                 case ETuple of
                    nothing ->
                      AddList;
                    _ ->
                      [{TimeP, ETuple} | AddList]
                  end;
              true ->
                 TimeP = get_time(Line),
                 Mult = get_payl(MACProtocol, Action, Line),
                 case Mult of
                    nothing ->
                      AddList;
                    _ ->
                      C = ckeck_pkg_multipath(HNode, AddList, TimeP, Mult),
                      Res = ets:lookup(EtsTable, multipath),
                      case Res of
                        [{multipath, ListMultipath}] ->
                          ets:insert(EtsTable, {multipath, [C | ListMultipath] });
                        _ ->
                          ets:insert(EtsTable, {multipath, [C] })
                      end,

                      AddList
                  end
              end,

              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, Line, TAddList);
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
              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, Line, AddList);
            _ ->
              Time = get_time(OLine),
              RTuple = get_tuple(Action, OLine),
              Payl = get_payl(MACProtocol, Action, OLine),
              extract_payl(HNode, EtsTable, Action, RTuple, NL_Protocol, Time, Payl, add),
              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, Line, AddList)
            end;
        nomatch ->
          case Action of
            intervals ->
              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, Line, AddList);
            source_data ->
              case re:run(Line, "(.*)Source Data:(.*) Len:(.*)State:(.*) Total:(.*)Hops:([0-9]+)(.*)>>", [dotall,{capture, all_but_first, binary}]) of
                {match, [_, M, _, S, _, H, _]} ->
                  ets:insert(EtsTable, {{source_data, M}, {S, bin_to_num(H) } });
                nomatch ->
                  nothing
              end,
              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, Line, AddList);
            _ ->
              get_all_lines(HNode, EtsTable, MACProtocol, NL_Protocol, Action, Device, OLine ++ Line, AddList)
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

get_payl(_, multipath, Line) ->
  case re:run(Line, "(.*)Multipath LA ([0-9]+) from ([0-9]+) : (.*)", [dotall,{capture, all_but_first, binary}]) of
    {match,[_, Addr1, Addr2, MultLine]} ->
       ML = binary_to_list(MultLine),
       SL = re:replace(ML, "n", ";", [global, {return, list}]),
       ResM = re:replace(SL, "[^0-9; ]", "", [global, {return, list}]),
       {bin_to_num(Addr1), bin_to_num(Addr2), ResM};
    nomatch ->
      nothing
  end;
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
extract_payl(_, _, _, _, _, _, nothing, _) ->
  [];
%----------------------------------- EXTRACT SEND PAYLOAD---------------
extract_payl(HNode, EtsTable, send, STuple, icrpr, Time, Payl, Add) ->
  [RSrc] = STuple,
  [Flag, PkgID, Src, Dst, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
  case nl_mac_hf:num2flag(Flag, nl) of
    data ->
      [Path, BData] = nl_mac_hf:extract_path_data(nothing, Data),
      add_data(EtsTable, {PkgID, BData, Src, Dst}, {send, HNode, RSrc, Time, Path}, Add),
      {data, PkgID, RSrc, BData};
    ack ->
      Hops = nl_mac_hf:extract_ack(nothing, Data),
      add_data(EtsTable, {PkgID, ack, Dst, Src}, {send_ack, HNode, RSrc, Time, Hops}, Add),
      {ack, PkgID, RSrc, Data};
    dst_reached ->
      nothing;
    _ ->
      nothing
  end;
extract_payl(HNode, EtsTable, send, STuple, NLProtocol, Time, Payl, Add) when NLProtocol =:= sncfloodr;
                                                                         NLProtocol =:= sncfloodrack;
                                                                         NLProtocol =:= dpffloodr;
                                                                         NLProtocol =:= dpffloodrack->
  [RSrc] = STuple,
  [Flag, PkgID, Src, Dst, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
  case nl_mac_hf:num2flag(Flag, nl) of
    data ->
      add_data(EtsTable, {PkgID, Data, Src, Dst}, {send, HNode, RSrc, Time}, Add),
      {data, PkgID, RSrc, Data};
    ack ->
      Hops = nl_mac_hf:extract_ack(nothing, Data),
      add_data(EtsTable, {PkgID, ack, Dst, Src}, {send_ack, HNode, RSrc, Time, Hops}, Add),
      {ack, PkgID, RSrc, Data};
    dst_reached ->
      nothing;
    _ ->
      nothing
  end;
%----------------------------------- EXTRACT RECV PAYLOAD---------------
extract_payl(HNode, EtsTable, recv, RTuple, icrpr, Time, Payl, Add) ->
  if RTuple == nothing;
     Payl == <<>> ->
    nothing;
  true ->
    [RSrc, RDst, Rssi, Integrity, Velocity] = RTuple,
    [Flag, PkgID, Src, Dst, Data] = nl_mac_hf:extract_payload_nl_flag(Payl),
    case nl_mac_hf:num2flag(Flag, nl) of
      data ->
        [Path, BData] = nl_mac_hf:extract_path_data(nothing, Data),
        add_data(EtsTable, {PkgID, BData, Src, Dst}, {recv, HNode, Time, RSrc, RDst, Rssi, Integrity, Velocity, Path}, Add),
        {data, PkgID, RSrc, RDst, BData};
      ack ->
        Hops = nl_mac_hf:extract_ack(nothing, Data),
        add_data(EtsTable, {PkgID, ack, Dst, Src}, {recv_ack, HNode, Time, RSrc, RDst, Hops}, Add),
        {ack, PkgID, RSrc, RDst, Data};
      dst_reached ->
        nothing;
      _ ->
        nothing
    end
  end;
extract_payl(HNode, EtsTable, recv, RTuple, NLProtocol, Time, Payl, Add) when NLProtocol=:= sncfloodr;
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
        add_data(EtsTable, {PkgID, Data, Src, Dst}, {recv, HNode, Time, RSrc, RDst, Rssi, Integrity, Velocity}, Add),
        {data, PkgID, RSrc, RDst, Data};
      ack ->
        Hops = nl_mac_hf:extract_ack(nothing, Data),
        add_data(EtsTable, {PkgID, ack, Dst, Src}, {recv_ack, HNode, Time, RSrc, RDst, Hops}, Add),
        {ack, PkgID, RSrc, RDst, Data};
      dst_reached ->
        nothing;
      _ ->
        nothing
    end
  end.


% IdTuple = {PkgID, Data, Src, Dst}
% {send, RSrc, TimeSend}  or {send, RSrc, TimeSend, Path}
% {recv, HNode, TimeRecv, RSrc, RDst, Rssi, Integrity, Velocity}
add_data(_EtsTable, _IdTuple, _VTuple, noadd) ->
  nothing;
add_data(EtsTable, IdTuple, VTuple, add) ->
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


sync_time(Table, NLProtocol, EtsTable, DeltaTable) ->
  sync_time(Table, [], NLProtocol, EtsTable, DeltaTable).

sync_time([], SyncTable, _, _, _) ->
  SyncTable;
sync_time([Pkg | T], SyncTable, NLProtocol, EtsTable, DeltaTable) ->
  SyncPkg = sync_pkg(Pkg, NLProtocol, EtsTable, DeltaTable),
  sync_time(T, [SyncPkg | SyncTable], NLProtocol, EtsTable, DeltaTable).

sync_pkg(Pkg, NLProtocol, EtsTable, DeltaTable) ->
  case NLProtocol of
    icrpr ->
      {Intv, [{ IdTuple, {RelayTuple, AckTuple}}]} = Pkg,
      {_PkgId, _Data, Src, Dst} = IdTuple,

      {[NS, NR, LNSent, LNRecv, Params, SPath, RPath], Stats } =
      case RelayTuple of
        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp},
        {paths_sent, SPathTmp},
        {paths_recv, RPathTmp}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp, SPathTmp, RPathTmp], []};

        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp},
        {stats, TStats},
        {paths_sent, SPathTmp},
        {paths_recv, RPathTmp}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp, SPathTmp, RPathTmp], TStats}
      end,

      {ack, {
      {send_ack, SendAck},
      {recv_ack, RecvAck}}} = AckTuple,

      ets:insert(EtsTable, {sync_neighbours, [Src]}),
      [Ns, NewLNSent, NewLNRecv] = start_sync_neighbour(Src, Dst, LNSent, LNRecv, DeltaTable),
      [NewSendAck, NewRecvAck] = sync_ack(Src, Dst, SendAck, RecvAck, Ns, Stats, DeltaTable),

      NewAckTuple =
      {ack, {
      {send_ack, NewSendAck},
      {recv_ack, NewRecvAck}}},

      SyncRelayTuple =
      case Stats of
        [] ->
          {{nodes_sent, NS},
          {nodes_recv, NR},
          {time_sent, NewLNSent},
          {time_recv, NewLNRecv},
          {params, Params},
          {paths_sent, SPath},
          {paths_recv, RPath}};
        _ ->
          {{nodes_sent, NS},
          {nodes_recv, NR},
          {time_sent, NewLNSent},
          {time_recv, NewLNRecv},
          {params, Params},
          {stats, Stats},
          {paths_sent, SPath},
          {paths_recv, RPath}}
      end,

      {Intv, [{ IdTuple, {SyncRelayTuple, NewAckTuple}}]};
    _ when NLProtocol =:= sncfloodrack;
           NLProtocol =:= dpffloodrack ->

      {Intv, [{ IdTuple, {RelayTuple, AckTuple}}]} = Pkg,
      {_PkgId, _Data, Src, Dst} = IdTuple,

      {[NS, NR, LNSent, LNRecv, Params], Stats } =
      case RelayTuple of
        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp], []};

        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp},
        {stats, TStats}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp], TStats}
      end,

      {ack, {
      {send_ack, SendAck},
      {recv_ack, RecvAck}}} = AckTuple,

      ets:insert(EtsTable, {sync_neighbours, [Src]}),
      [Ns, NewLNSent, NewLNRecv] = start_sync_neighbour(Src, Dst, LNSent, LNRecv, DeltaTable),
      [NewSendAck, NewRecvAck] = sync_ack(Src, Dst, SendAck, RecvAck, Ns, Stats, DeltaTable),

      SyncRelayTuple =
      case Stats of
        [] ->
          {{nodes_sent, NS},
          {nodes_recv, NR},
          {time_sent, NewLNSent},
          {time_recv, NewLNRecv},
          {params, Params}};
        _ ->
          {{nodes_sent, NS},
          {nodes_recv, NR},
          {time_sent, NewLNSent},
          {time_recv, NewLNRecv},
          {params, Params},
          {stats, Stats}}
      end,

      NewAckTuple =
      {ack, {
      {send_ack, NewSendAck},
      {recv_ack, NewRecvAck}}},

      %TODO SYnc Ack tuple
      {Intv, [{ IdTuple, {SyncRelayTuple, NewAckTuple}}]};

    _ ->
      {Intv, {IdTuple, RelayTuple}} = Pkg,
      {_PkgId, _Data, Src, Dst} = IdTuple,

      {{nodes_sent, NS},
      {nodes_recv, NR},
      {time_sent, LNSent},
      {time_recv, LNRecv},
      {params, Params}} = RelayTuple,

      ets:insert(EtsTable, {sync_neighbours, [Src]}),
      [_Ns, NewLNSent, NewLNRecv] =
      start_sync_neighbour(Src, Dst, LNSent, LNRecv, DeltaTable),

      SyncRelayTuple = {{nodes_sent, NS},
      {nodes_recv, NR},
      {time_sent, NewLNSent},
      {time_recv, NewLNRecv},
      {params, Params}},

      %TODO SYnc Ack tuple
      {Intv, { IdTuple, SyncRelayTuple}}
  end.

sync_ack(Src, Dst, SendAck, RecvAck, Ns, Stats, DeltaTable) ->
  NewSendAck =
  lists:foldr(
  fun(X, A) ->
      case X of
        {Dst, BDst, TimeSent, Hops} ->
          case ets:lookup(DeltaTable, Dst) of
            [{Dst, _Delta}] ->
              TS = TimeSent, % + Delta,
              [ {Dst, BDst, TS, Hops} | A];
            _ ->
              [ X | A]
          end;
        _ -> [ X | A]
      end
  end, [], SendAck),

  CheckAck =
  lists:foldr(
  fun(X, A) ->
      case X of
        {Src, _, _, _} ->
          true;
        _ -> A
      end
  end, false, RecvAck),

  [NNewSendAck, NewRecvAck] =
  if CheckAck -> [NewSendAck, RecvAck];
  true ->
    spec_sync_ack(Src, Dst, NewSendAck, RecvAck, Ns, Stats, DeltaTable)
  end,

  ets:delete_all_objects(DeltaTable),
  [NNewSendAck, NewRecvAck].

spec_sync_ack(Src, Dst, SendAck, RecvAck, Ns, Stats, DeltaTable) ->
  case Stats of
    {<<"Delivered">>, Hops} ->
      spec_sync_ack_helper(Src, Dst, SendAck, RecvAck, Ns, Hops, DeltaTable);
    _ -> [SendAck, RecvAck]
  end.

spec_sync_ack_helper(Src, Dst, SendAck, RecvAck, Ns, Hops, DeltaTable) ->
  Neighbours =
  lists:foldr(
  fun(X, A) ->
      case X of
        {_, _, Src, N} ->
          N;
        _ -> A
      end
  end, [], Ns),

  {NewSendAck, NewRecvAck} =
  lists:foldr(
  fun(X, {A, Rack}) ->
    {Addr, BDst, TimeSent, NHops} = X,
    case lists:member(Addr, Neighbours) of
      true ->
        HopsCount = (NHops + 1) == Hops,
        case ets:lookup(DeltaTable, Addr) of
            [{Addr, _Delta}] when HopsCount ->
              TS = TimeSent, % + Delta,
              TSL = [ {Addr, BDst, TS, NHops} | A],
              Dist = distance(Src, Addr),
              TransmissionTime = (Dist / ?SOUND_SPEED + ?SIGNAL_LENGTH)  * 1000000,

              NumberHops =
              if(BDst == Dst) -> 0;
                true -> Hops
              end,

              TRL = [ {Src, Addr, 255, TS + TransmissionTime, NumberHops} | Rack],
              {TSL , TRL};
            _ ->
              {[ X | A], Rack}
          end;
      false -> {[X | A], Rack}
    end
  end, {[], RecvAck}, SendAck),

  [NewSendAck, NewRecvAck].


start_sync_neighbour(Src, _Dst, LNSent, LNRecv, DeltaTable) ->
  Ns = neighbours_list(Src, LNRecv),

  NewNs = check_neigbour_list(Src, Ns),
  [UNs, NewLNSent, NewLNRecv] = start_sync(NewNs, LNSent, LNRecv, DeltaTable, LNSent, LNRecv),

  [UNs, NewLNSent, NewLNRecv].

start_sync(Ns, LNSent, LNRecv, DeltaTable, NewLNSent, NewLNRecv) ->
  {Src, Neighbours} =
  lists:foldr(
  fun(X, A) ->
      case X of
        {s, nsn, Addr, N} ->
          {Addr, N};
        _ -> A
      end
  end, {[], []}, Ns),

  if(Neighbours == []) ->
    NSync =
    lists:foldr(
    fun(X, A) ->
      case X of
        {ns, _, _, _} -> true;
        _ -> A
      end
    end, false, Ns),
    if(NSync) -> spec_sync(Ns, NewLNSent, NewLNRecv);
    true ->
      [Ns, NewLNSent, NewLNRecv]
    end;
  true ->
    sync_neighbours(Src, Neighbours, Ns, LNSent, LNRecv, DeltaTable, NewLNSent, NewLNRecv)
  end.


spec_sync(Ns, NewLNSent, NewLNRecv) ->
  [Ns, NewLNSent, NewLNRecv].

sync_neighbours(Src, Neighbours, Ns, LNSent, LNRecv, DeltaTable, NewLNSent, NewLNRecv) ->
  [NewNs, NNewLNSent, NNewLNRecv] =
  lists:foldr(
  fun(X, [NTNs, NTSent, NTrecv]) ->
    {State, _NS, RAddr, _} = X,
    StMember = ((lists:member(RAddr, Neighbours))), %and (State == ns) ),
    if StMember ->
      [NNTSent, NNTrecv] = sync(Src, RAddr, LNSent, LNRecv, DeltaTable, NTSent, NTrecv, State),
      NewTNs = changeNs(NTNs, Src, RAddr, all),
      [NewTNs, NNTSent, NNTrecv];
    true ->
      NewTNs = changeNs(NTNs, Src, RAddr, src),
      [NewTNs, NTSent, NTrecv]
    end
  end, [Ns, NewLNSent, NewLNRecv], Ns),

  start_sync(NewNs, LNSent, LNRecv, DeltaTable, NNewLNSent, NNewLNRecv).

sync(Src, RAddr, _LNSent, _LNRecv, DeltaTable, NewLNSent, NewLNRecv, State) ->
  Send_time = get_time_sent_interval_t(Src, NewLNSent),

  _Delta =
  lists:foldr(
    fun(X, A) ->
      case X of
        {RAddr, Src, RTimeStamp} ->
          DT = find_delta_t(Src, Send_time, RAddr, RTimeStamp),
          case ets:lookup(DeltaTable, RAddr) of
            [{RAddr, _}] -> nothing;
            _  -> ets:insert(DeltaTable, { RAddr, DT})
          end,
          DT;
        _ ->
          A
      end
    end, 0, NewLNRecv),

  NNewLNRecv =
  lists:foldr(fun(X, A) ->
    case X of
      {RAddr, Src, RTimeStamp} ->
        Rcv = RTimeStamp, % + Delta,
        if (Rcv > 0) -> [ {RAddr, Src, Rcv} | A]; true -> [X | A] end;
      _->
        [X | A]
    end
  end, [], NewLNRecv),

  NNewNLSent =
  lists:foldr(fun(X, A) ->
    case X of
      {RAddr, TAddr, STimeStamp} ->
        %if (State == ns) -> [ {RAddr, TAddr, STimeStamp + Delta} | A] ; true -> [X | A] end;
        if (State == ns) -> [ {RAddr, TAddr, STimeStamp} | A] ; true -> [X | A] end;
      _->
        [X | A]
    end
  end, [], NewLNSent),

  [NNewNLSent, NNewLNRecv].

get_time_sent_interval_t(Addr, T) ->
  lists:foldr(
  fun(X, A) ->
    case X of
      {Addr, _, SendTime} -> SendTime;
      _ -> A
    end
  end, 0, T).


find_delta_t(Src, STimeStamp, Dst, RTimeStamp) ->
  Dist = distance(Src, Dst),
  %TODO length  of impulse
  TransmissionTime = (Dist / ?SOUND_SPEED + ?SIGNAL_LENGTH)  * 1000000,
  RTimeStamp - STimeStamp - TransmissionTime.


changeNs(Ns, Src, Addr, St) ->
  lists:foldr(
  fun(X, A) ->
    case X of
      {_, SN, Addr, N} when St =:= all->
        [{s, SN, Addr, N} | A ];
      {_, _, Src, N} ->
        [{s, sn, Src, N} | A ];
      _ -> [X | A]
    end
  end, [], Ns).

% ns - not synchronized
% s -  synchronized
% nsn - not synchronized neighbours
% sn - synchronized neighbours

neighbours_list(Src, LNRecv) ->
  lists:foldr(
  fun(X, A) ->
    {XNAddr, _Addr, _RTimeStamp} = X,
    Ns = find_neighbours(XNAddr, LNRecv),
    State =
    if(XNAddr == Src) -> s;
      true -> ns
    end,
    T = {State, nsn, XNAddr, Ns},
    Member = lists:member(T, A),
    if(not Member) -> [ T | A]; true -> A end
  end, [], LNRecv).

check_neigbour_list(Src, Ns) ->
  Inside =
  lists:foldr(
  fun(X, A) ->
    case X of
      {_State, _StateN, Src, _Neighbours} -> true;
      _ -> A
    end
  end, false, Ns),
  if Inside == true ->
    Ns;
  true ->
    NNs =
    lists:foldr(
    fun(X, A) ->
      case X of
        {_State, _StateN, Addr, Neighbours} ->
          Member = lists:member(Src, Neighbours),
          if Member -> [Addr | A];
          true -> A end;
        _ -> A
      end
    end, [], Ns),
    [{s, nsn, Src, NNs} | Ns]
  end.


find_neighbours(Addr, List) ->
  lists:foldr(
    fun(X, A) ->
      case X of
        {NAddr, Addr, _RTimeStamp} ->
          Member = lists:member(NAddr, A),
          if(not Member) -> [ NAddr | A]; true -> A end;
        {Addr, NAddr, _RTimeStamp} ->
          Member = lists:member(NAddr, A),
          if(not Member) -> [ NAddr | A]; true -> A end;
        _ ->
          A
      end
    end, [], List).

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

      LNSent =
      case RelayTuple of
        {{nodes_sent, _NS},
        {nodes_recv, _NR},
        {time_sent, LNSentTmp},
        {time_recv, _LNRecv},
        {params, _Params},
        {stats, _Stats},
        {paths_sent, _SPath},
        {paths_recv, _RPath}} -> LNSentTmp;

        {{nodes_sent, _NS},
        {nodes_recv, _NR},
        {time_sent, LNSentTmp},
        {time_recv, _LNRecv},
        {params, _Params},
        {paths_sent, _SPath},
        {paths_recv, _RPath}} -> LNSentTmp
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
              {stats, { State, Hops}},
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

analyse(EtsTable, MACProtocol, NLProtocol) ->
  Table = cat_data_ack(EtsTable),
  AddTable = prepare_add_info(EtsTable, Table, NLProtocol),

  Is = ?INTERVALS,

  OIntervals =
  lists:foldr(fun(X, A) ->
    Res = ets:lookup(EtsTable, {interval, ?SRC, X}),
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

  EtsSyncTable = ets:new(sync_links, [set, named_table]),
  DeltaTable = ets:new(delta_table, [set, named_table]),
  SyncTable = sync_time(TableIntervals, NLProtocol, EtsSyncTable, DeltaTable),

  {Title, TitleStats} =
  case NLProtocol of
    sncfloodr ->
      {io_lib:format("MACProtocol,NLProtocol,Interval,Src,Dst,PkgLength,TimeTillDst(s),PATH,[Addr1;Addr2;RSSi;Integrity;Velocity]~n", []),
      io_lib:format("MACProtocol,NLProtocol,Interval,Src,Dst,TimeExp(min),IfDeliveredDst~n", [])};
    dpffloodr ->
      {io_lib:format("MACProtocol,NLProtocol,Interval,Src,Dst,PkgLength,TimeTillDst(s),PATH,[Addr1;Addr2;RSSi;Integrity;Velocity]~n", []),
      io_lib:format("MACProtocol,NLProtocol,Interval,Src,Dst,IfDeliveredDst~n", [])};
    icrpr ->
      {io_lib:format("MACProtocol,NLProtocol,Interval,Src,Dst,PkgLength,TimeTillDst(s),TimeAck(s),PATH,Hops,PATHACK,[Addr1;Addr2;RSSi;Integrity;Velocity]~n", []),
      io_lib:format("MACProtocol,NLProtocol,Interval,Src,Dst,IfDeliveredDst,IfDeliveredAck,Hops~n", [])};
    sncfloodrack ->
      {io_lib:format("MACProtocol,NLProtocol,Interval,Src,Dst,PkgLength,TimeTillDst(s),TimeAck(s),PATH,Hops,PATHACK,[Addr1;Addr2;RSSi;Integrity;Velocity]~n", []),
      io_lib:format("MACProtocol,NLProtocol,Interval,Src,Dst,IfDeliveredDst,IfDeliveredAck,Hops~n", [])};
    dpffloodrack ->
      {io_lib:format("MACProtocol,NLProtocol,Interval,Src,Dst,PkgLength,TimeTillDst(s),TimeAck(s),PATH,Hops,PATHACK,[Addr1;Addr2;RSSi;Integrity;Velocity]~n", []),
      io_lib:format("MACProtocol,NLProtocol,Interval,Src,Dst,IfDeliveredDst,IfDeliveredAck,Hops~n", [])}
  end,

  ets:delete_all_objects(DeltaTable),
  A8 = convet_to_csv(8, MACProtocol, NLProtocol, SyncTable, DeltaTable, EtsTable),
  A15 = convet_to_csv(15, MACProtocol, NLProtocol, SyncTable, DeltaTable, EtsTable),
  A4 = convet_to_csv(4, MACProtocol, NLProtocol, SyncTable, DeltaTable, EtsTable),


  StatsTable = ets:new(stats_table, [set, named_table]),
  {ExpStart15, ExpEnd15, Stats15} = count_stats(15, MACProtocol, NLProtocol, SyncTable, StatsTable),
  GetStats15 = get_stats(15, StatsTable, NLProtocol),
  LengthExp15 = (ExpEnd15 - ExpStart15) / 1000000 / 60,

  {ExpStart8, ExpEnd8, Stats8} = count_stats(8, MACProtocol, NLProtocol, SyncTable, StatsTable),
  GetStats8 = get_stats(8, StatsTable, NLProtocol),
  LengthExp8 = (ExpEnd8 - ExpStart8) / 1000000 / 60,

  {ExpStart4, ExpEnd4, Stats4} = count_stats(4, MACProtocol, NLProtocol, SyncTable, StatsTable),
  GetStats4 = get_stats(4, StatsTable, NLProtocol),
  LengthExp4 = (ExpEnd4 - ExpStart4) / 1000000 / 60,

  TitleA15 = [Title | A15],
  A = [TitleA15 | A8],
  AA = [A | A4],

  [SLengthExp15] =  io_lib:format("~.6f", [LengthExp15]),
  [SLengthExp8] =  io_lib:format("~.6f", [LengthExp8]),
  [SLengthExp4] =  io_lib:format("~.6f", [LengthExp4]),

  Desr = "\n[Hops/Count/CountAck/TotalCount] --> LengthExp \n",
  ResStats15 = TitleStats ++ Stats15 ++ Desr  ++ "  "++ GetStats15 ++ "  " ++ SLengthExp15  ++ "\n",
  ResStats8 = TitleStats ++ Stats8 ++ Desr ++ "  " ++ GetStats8 ++ "  " ++ SLengthExp8 ++ "\n",
  ResStats4 = TitleStats ++ Stats4 ++ Desr ++ "  " ++ GetStats4 ++ "  " ++ SLengthExp4 ++ "\n",
  ResStats = ResStats15 ++ ResStats8 ++ ResStats4,

  [{path, Dir}] = ets:lookup(EtsTable, path),
  file:delete(Dir ++ "/res.log"),
  file:write_file(Dir ++ "/res.log", io_lib:fwrite("~p ~n", [SyncTable])),

  file:delete(Dir ++ "/res_csv.xls"),
  file:write_file(Dir ++ "/res_csv.xls", io_lib:fwrite("~s ~n", [AA])),

  file:delete(Dir ++ "/res_stats_csv.xls"),
  file:write_file(Dir ++ "/res_stats_csv.xls", io_lib:fwrite("~s ~n", [ResStats])),

  io:format(" ~p~n", [CountIntPkg]),
  io:format(" ~p~n", [Intervals]).


check_recv(Dst, LNRecv) ->
  lists:foldr(
  fun(X, A) ->
    case X of
      {Dst, _, _} -> 1;
      _ -> A
    end
  end, 0, LNRecv).

check_recv_ack(Src, RecvAck, Stats) ->
  Res =
  lists:foldr(
  fun(X, A) ->
    case X of
      {Src, _, _, _, Hops} -> {1, Hops};
      _ -> A
    end
  end, {0, 0}, RecvAck),

  case Res of
    {0, 0} ->
      case check_recv_state_ack(Stats) of
        {ResState, ResHops} -> [ResState, ResHops];
        _ -> {0, 0}
      end;
    {ResState, ResHops} ->
      [ResState, ResHops]
  end.

check_recv_state_ack({State, Hops}) ->
  case State of
      <<"Delivered">> -> {1, Hops};
      <<"Failed">> -> {0, Hops};
      _ -> {0, Hops}
  end;
check_recv_state_ack(Stats) ->
  lists:foldr(
  fun(X, A) ->
    case X of
      {<<"Delivered">>, Hops} -> {1, Hops};
      {<<"Failed">>, Hops} -> {0, Hops};
      _ -> A
    end
  end, {0, 0}, Stats).

get_stats(Intv = 15, StatsTable, NLProtocol) when NLProtocol =:= sncfloodr;
                                                  NLProtocol =:= dpffloodr->
  {Total, Count} =
  case ets:lookup(StatsTable, Intv) of
    [{Intv, {TC, C}}] -> {TC, C};
    _ ->  {0, 0}
  end,
  LTotal = integer_to_list(Total),
  LCount = integer_to_list(Count),
  LCount ++ "/" ++ LTotal;

get_stats(Intv, StatsTable, _NLProtocol) ->
  Str =
  lists:foldr(
    fun(X, A) ->
      case ets:lookup(StatsTable, {Intv, X}) of
        [{ {Intv, X}, {TC, C, CA}}] ->
          LX = integer_to_list(X),
          LTC = integer_to_list(TC),
          LC = integer_to_list(C),
          LCA = integer_to_list(CA),
          L = LX ++ "/" ++ LC ++ "/" ++ LCA ++ "/" ++ LTC,
          L ++ ";" ++  A;
        _ ->  A
      end
  end, "", [0, 1, 2, 3, 4, 5]),
  if (Str =/= []) ->
    string:left(Str, length(Str) - 1, $.);
  true ->
    ""
  end.

count_stats_helper(Intv, StateRecv, StatsTable) ->
  {TotalCount, Count} =
  case ets:lookup(StatsTable, Intv) of
    [{Intv, {TC, C}}] -> {TC, C};
    _ ->  {0, 0}
  end,
  ets:insert(StatsTable, {Intv,  {TotalCount + 1, Count + StateRecv}   }).

count_stats_helper(Intv, StateRecv, StateRecvAck, Hops, StatsTable) ->
  {TotalCount, Count, CountAck} =
  case ets:lookup(StatsTable, {Intv, Hops}) of
    [{ {Intv, Hops}, {TC, C, CA}}] -> {TC, C, CA};
    _ ->  {0, 0, 0}
  end,
  ets:insert(StatsTable, {{Intv, Hops},  {TotalCount + 1, Count + StateRecv, CountAck + StateRecvAck}} ).


check_limit_exp(Data, Src, LNSent, MinS, MaxS) ->
  case re:run(Data, "([^:]*):XXXXXXXXXXXXXXXXXXXXXX", [dotall,{capture, all_but_first, binary}]) of
    {match, [_Interval]} ->
      {MinS, MaxS};
    nomatch ->
      TS = get_sent_time(Src, LNSent),
      case {MinS, MaxS} of
        {0, 0} ->
          {TS, TS};
        _ ->
          NewMin =
          if (TS < MinS) -> TS; true -> MinS end,
          NewMax =
          if (TS > MaxS) -> TS; true -> MaxS end,
          {NewMin, NewMax}
      end
  end.

get_sent_time(Src, LNSent) ->
  lists:foldr(
  fun(X, A) ->
    case X of
      {Src, _, Time} when A =/= 0 ->
        if Time < A -> Time; true -> A end;
      {Src, _, Time} -> Time;
      {Src, _, Time, _} -> Time;
      _ -> A
    end
  end, 0, LNSent).

count_stats(SortInv, MACProtocol, NLProtocol, SyncTable, StatsTable) when NLProtocol =:= sncfloodr;
                                                                          NLProtocol =:= dpffloodr ->
  lists:foldr(
    fun(X, {MinS, MaxS, AStr}) ->
      {Intv, {IdTuple, RelayTuple}} = X,
      {_PkgId, Data, Src, Dst} = IdTuple,

      {{nodes_sent, _NS},
      {nodes_recv, _NR},
      {time_sent, LNSent},
      {time_recv, LNRecv},
      {params, _Params}} = RelayTuple,

      if (Intv == SortInv) ->
        StateRecv  = check_recv(Dst, LNRecv),
        count_stats_helper(Intv, StateRecv, StatsTable),
        PrintL = [MACProtocol, NLProtocol, Intv, Src, Dst, StateRecv],
        T = io_lib:format("~w,~w,~w,~w,~w,~w~n", PrintL),
        LT = lists:flatten(T),

        {TMinS, TMaxS} = check_limit_exp(Data, Src, LNSent, MinS, MaxS),
        {TMinS, TMaxS, [ LT | AStr]};
      true ->
        {MinS, MaxS, AStr}
      end
    end, {0, 0, []}, SyncTable);

count_stats(SortInv, MACProtocol, NLProtocol, SyncTable, StatsTable) when NLProtocol =:= icrpr ->
  lists:foldr(
    fun(X, {MinS, MaxS, AStr}) ->
      {Intv, [{ IdTuple, {RelayTuple, AckTuple}}]} = X,
      {_PkgId, Data, Src, Dst} = IdTuple,

      {[_NS, _NR, LNSent, LNRecv, _Params, _SPath, _RPath], Stats } =
      case RelayTuple of
        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp},
        {paths_sent, SPathTmp},
        {paths_recv, RPathTmp}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp, SPathTmp, RPathTmp], []};

        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp},
        {stats, TStats},
        {paths_sent, SPathTmp},
        {paths_recv, RPathTmp}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp, SPathTmp, RPathTmp], TStats}
      end,

      {ack, {
      {send_ack, _SendAck},
      {recv_ack, RecvAck}}} = AckTuple,

      if (Intv == SortInv) ->
        StateRecv  = check_recv(Dst, LNRecv),
        [StateRecvAck, Hops]  = check_recv_ack(Src, RecvAck, Stats),
        count_stats_helper(Intv, StateRecv, StateRecvAck, Hops, StatsTable),
        PrintL = [MACProtocol, NLProtocol, Intv, Src, Dst, StateRecv, StateRecvAck, Hops],
        T = io_lib:format("~w,~w,~w,~w,~w,~w,~w,~w~n", PrintL),
        LT = lists:flatten(T),
        {TMinS, TMaxS} = check_limit_exp(Data, Src, LNSent, MinS, MaxS),
        {TMinS, TMaxS, [ LT | AStr]};
      true ->
        {MinS, MaxS, AStr}
      end
  end, {0, 0, []}, SyncTable);

count_stats(SortInv, MACProtocol, NLProtocol, SyncTable, StatsTable) when NLProtocol =:= sncfloodrack;
                                                                          NLProtocol =:= dpffloodrack ->
  lists:foldr(
    fun(X, {MinS, MaxS, AStr}) ->
      {Intv, [{ IdTuple, {RelayTuple, AckTuple}}]} = X,
      {_PkgId, Data, Src, Dst} = IdTuple,

      {[_NS, _NR, LNSent, LNRecv, _Params], Stats } =
      case RelayTuple of
        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp], []};

        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp},
        {stats, TStats}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp], TStats}
      end,

      {ack, {
      {send_ack, _SendAck},
      {recv_ack, RecvAck}}} = AckTuple,

      if (Intv == SortInv) ->
        StateRecv  = check_recv(Dst, LNRecv),
        [StateRecvAck, Hops]  = check_recv_ack(Src, RecvAck, Stats),
        count_stats_helper(Intv, StateRecv, StateRecvAck, Hops, StatsTable),
        PrintL = [MACProtocol, NLProtocol, Intv, Src, Dst, StateRecv, StateRecvAck, Hops],
        T = io_lib:format("~w,~w,~w,~w,~w,~w,~w,~w~n", PrintL),
        LT = lists:flatten(T),
        {TMinS, TMaxS} = check_limit_exp(Data, Src, LNSent, MinS, MaxS),
        {TMinS, TMaxS, [ LT | AStr]};
      true ->
        {MinS, MaxS, AStr}
      end
    end, {0, 0, []}, SyncTable).

getMultipath(EtsTable, PkgId, Data, LRecv, LRecvAck) ->
  case ets:lookup(EtsTable, multipath) of
    [{multipath, MultTuple}] ->
        lists:foldr(
        fun(X, {DataA, AckA}) ->
            case X of
              {data, PkgId, HNode, FromAddr, Data, ResM} ->
                Time = getTime(FromAddr, LRecv, recv),
                if(Time =/= 0) ->
                  PL = re:replace(ResM, "(    ;|  ;)", ";", [global, {return, list}]),
                  NL = re:replace(PL, "(     |   )", " ", [global, {return, list}]),
                  To = integer_to_list(HNode),
                  From = integer_to_list(FromAddr),
                  Str = To ++ ";" ++ From ++ ";" ++ NL,
                  {Str ++ DataA, AckA};
                true ->
                  {DataA, AckA}
                end;
              {ack, PkgId, HNode, FromAddr, _Data, ResM} ->
                Time = getTime(FromAddr, LRecvAck, recv_ack),
                if(Time =/= 0) ->
                  PL = re:replace(ResM, "(    ;|  ;)", ";", [global, {return, list}]),
                  NL = re:replace(PL, "(     |   )", " ", [global, {return, list}]),
                  To = integer_to_list(HNode),
                  From = integer_to_list(FromAddr),
                  Str = To ++ ";" ++ From ++ ";" ++ NL,
                  {DataA, Str ++ AckA};
                true ->
                  {DataA, AckA}
                end;
              _ ->
                {DataA, AckA}
            end
        end, {"", ""}, MultTuple);
    _->
      {"", ""}
  end.

convet_to_csv(SortInv, MACProtocol, NLProtocol, SyncTable, DeltaTable, _EtsTable) when NLProtocol =:= sncfloodr;
                                                                          NLProtocol =:= dpffloodr ->
  lists:foldr(
    fun(X, AStr) ->
      {Intv, {IdTuple, RelayTuple}} = X,
      {_PkgId, Data, Src, Dst} = IdTuple,

      {{nodes_sent, _NS},
      {nodes_recv, _NR},
      {time_sent, LNSent},
      {time_recv, LNRecv},
      {params, Params}} = RelayTuple,

      if (Intv == SortInv) ->
        ParamsL = getParams(Params),
        PkgLength = length(binary_to_list(Data)) + 4,

        {_DT, TimeTillDstF, PathDirect} = findPaths(Src, Dst, LNSent, [], LNRecv, 0, NLProtocol, DeltaTable, direct),
        PrintL = [MACProtocol, NLProtocol, Intv, Src, Dst, PkgLength, TimeTillDstF, PathDirect, ParamsL],

        T = io_lib:format("~w,~w,~w,~w,~w,~w,~w,~s,~s~n", PrintL),
        LT = lists:flatten(T),
        [ LT | AStr];
        true -> AStr
      end
    end, [], SyncTable);

convet_to_csv(SortInv, MACProtocol, NLProtocol, SyncTable, DeltaTable, _EtsTable) when NLProtocol =:= icrpr ->
  lists:foldr(
    fun(X, AStr) ->
      {Intv, [{ IdTuple, {RelayTuple, AckTuple}}]} = X,
      {_PkgId, Data, Src, Dst} = IdTuple,

      {[_NS, _NR, LNSent, LNRecv, Params, _SPath, _RPath], _Stats } =
      case RelayTuple of
        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp},
        {paths_sent, SPathTmp},
        {paths_recv, RPathTmp}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp, SPathTmp, RPathTmp], []};

        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp},
        {stats, TStats},
        {paths_sent, SPathTmp},
        {paths_recv, RPathTmp}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp, SPathTmp, RPathTmp], TStats}
      end,

      {ack, {
      {send_ack, SendAck},
      {recv_ack, RecvAck}}} = AckTuple,

      if (Intv == SortInv) ->
        St = getTime(Src, LNSent, send),
        ParamsL = getParams(Params),

        {TimeAck, Hops, RSrc} =
        case getTime(Src, RecvAck, recv_ack) of
          {Rta, H, RS} ->
            {(Rta - St) / 1000000, H, RS};
          _ -> {0.0, 0, 0}
        end,

        [TimeAckL] = io_lib:format("~.4f", [TimeAck]),
        PkgLength = length(binary_to_list(Data)) + 4,
        {TimeAckF, _} = string:to_float(TimeAckL),

        {_DT, TimeTillDstF, PathDirect} = findPaths(Src, Dst, LNSent, SendAck, LNRecv, Hops, NLProtocol, DeltaTable, direct),
        {_DTAck, _TimeAckFTmp, PathAck} = findPaths(Dst, Src, LNSent, SendAck, RecvAck, Hops, NLProtocol, DeltaTable, back),

        NTimeAckF =
        if (TimeAckF < 0 ) or (TimeAckF > 100) ->
          Rt = getTime(RSrc, LNRecv, {recv_src, Src}),
          DT = find_delta_t(Src, St, RSrc, Rt),
          {NTimeAck, _, _} =
          case getTime(Src, RecvAck, recv_ack) of
            {TRta, TH, TRS} -> {TRta, TH, TRS};
            _ -> {0.0, 0, 0}
          end,
          (NTimeAck - DT - St) / 1000000;
        true ->
          TimeAckF
        end,

        PrintL = [MACProtocol, NLProtocol, Intv, Src, Dst, PkgLength, TimeTillDstF, NTimeAckF, PathDirect, Hops, PathAck, ParamsL],
        T = io_lib:format("~w,~w,~w,~w,~w,~w,~w,~w,~s,~w,~s,~s~n", PrintL),
        LT = lists:flatten(T),
        [ LT | AStr];
        true -> AStr
      end
  end, [], SyncTable);

convet_to_csv(SortInv, MACProtocol, NLProtocol, SyncTable, DeltaTable, EtsTable) when NLProtocol =:= sncfloodrack;
                                                                          NLProtocol =:= dpffloodrack ->
  lists:foldr(
    fun(X, AStr) ->
      {Intv, [{ IdTuple, {RelayTuple, AckTuple}}]} = X,
      {PkgId, Data, Src, Dst} = IdTuple,

      {[_NS, _NR, LNSent, LNRecv, Params], _Stats } =
      case RelayTuple of
        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp], []};

        {{nodes_sent, NSTmp},
        {nodes_recv, NRTmp},
        {time_sent, LNSentTmp},
        {time_recv, LNRecvTmp},
        {params, ParamsTmp},
        {stats, TStats}} ->
          {[NSTmp, NRTmp, LNSentTmp, LNRecvTmp, ParamsTmp], TStats}
      end,

      {ack, {
      {send_ack, SendAck},
      {recv_ack, RecvAck}}} = AckTuple,

      if (Intv == SortInv) ->
        St = getTime(Src, LNSent, send),
        ParamsL = getParams(Params),

        {TimeAck, Hops, RSrc} =
        case getTime(Src, RecvAck, recv_ack) of
          {Rta, H, RS} ->
            {(Rta - St) / 1000000, H, RS};
          _ -> {0.0, 0, 0}
        end,

        [TimeAckL] = io_lib:format("~.4f", [TimeAck]),
        PkgLength = length(binary_to_list(Data)) + 4,
        {TimeAckF, _} = string:to_float(TimeAckL),

        {_DT, TimeTillDstF, PathDirect} = findPaths(Src, Dst, LNSent, SendAck, LNRecv, Hops, NLProtocol, DeltaTable, direct),
        {_DTAck, _TimeAckFTmp, PathAck} = findPaths(Dst, Src, LNSent, SendAck, RecvAck, Hops, NLProtocol, DeltaTable, back),

        NTimeAckF =
        if (TimeAckF < 0 ) or (TimeAckF > 100) ->
          Rt = getTime(RSrc, LNRecv, {recv_src, Src}),
          DT = find_delta_t(Src, St, RSrc, Rt),
          {NTimeAck, _, _} =
          case getTime(Src, RecvAck, recv_ack) of
            {TRta, TH, TRS} -> {TRta, TH, TRS};
            _ -> {0.0, 0, 0}
          end,
          TT = (NTimeAck - DT - St) / 1000000,

          if(TT - TimeTillDstF < 3) and (TT > 0) ->
            TT * 2;
          true ->
            TT
          end;

        true ->
          if(TimeAckF - TimeTillDstF < 3) and (TimeAckF > 0) ->
            TimeTillDstF * 2 + TimeAckF;
          true ->
            TimeAckF
          end
        end,

        {MultipathLDirect, MultipathLAck} = getMultipath(EtsTable, PkgId, Data, LNRecv, RecvAck),
        PrintL = [MACProtocol, NLProtocol, Intv, Src, Dst, PkgLength, TimeTillDstF, NTimeAckF, PathDirect, Hops, PathAck, ParamsL, MultipathLDirect, MultipathLAck],
        T = io_lib:format("~w,~w,~w,~w,~w,~w,~w,~w,~s,~w,~s,~s,~s,~s~n", PrintL),
        LT = lists:flatten(T),
        [ LT | AStr];
        true -> AStr
      end
    end, [], SyncTable).


findPaths(Src, Dst, LNSent, SendAck, LNRecv, Hops, NLProtocol, EtsTable, Direction) ->
  Ns = get_rcv_neighbours(Dst, LNRecv),
  CurrPath = form_path(Dst, Ns, [{Dst}]),
  ProcessedNs = [Dst],
  findPathsHelper(Src, Dst, LNSent, SendAck, LNRecv, CurrPath, Ns, ProcessedNs, Hops, NLProtocol, EtsTable, Direction).

delete_no_coplete_path(Src, Dst, CurrPath) ->
  NCurrPath = lists:flatten(CurrPath),
  lists:foldr(
  fun(X, A) ->
    TL = tuple_to_list(X),
    Member = ((lists:member(Src, TL)) and (lists:member(Dst, TL))),
    if Member ->
      {_, _, ProcTL} =
      lists:foldr(fun(XX, {StS, StE, AA}) ->
        case XX of
          Dst -> {nstart, send, [XX | AA]};
          Src when (StS == nstart)-> {start, StE, [XX | AA]};
          _ when ((StE == send) and (StS == nstart)) -> {StS, StE, [XX | AA]};
          _ -> {StS, StE, AA} end
        end, {nstart, nend, []}, TL),

      Length = length(ProcTL),
      ProcTuple = list_to_tuple(ProcTL),
      MemberPath = lists:member(ProcTuple, A),
      if not MemberPath ->
        if(Length =< 5) ->
          [ ProcTuple | A];
        true -> A
        end;
      true -> A
      end;
    true -> A
    end
  end, [], NCurrPath).

path_to_str([], _) ->
  "";
path_to_str(NPath, back) ->
  Str =
  lists:foldr(
  fun(X, A) ->
     XT = tuple_to_list(X),
     PStr = lists:foldr( fun(XX, AA) -> integer_to_list(XX) ++ "->" ++ AA end, "", XT),
     S = string:left(PStr, length(PStr) - 2, $.),
     S ++ ";" ++ A
  end, "", NPath),

  if (Str =/= []) ->
    string:left(Str, length(Str) - 1, $.);
  true ->
    ""
  end;

path_to_str(NPath, direct) ->
  Str =
  lists:foldr(
  fun(X, A) ->
     {Time, Path} = X,
     [STime] = io_lib:format("~.4f", [Time]),
     XT = tuple_to_list(Path),
     PStr = lists:foldr( fun(XX, AA) -> integer_to_list(XX) ++ "->" ++ AA end, "", XT),
     S = string:left(PStr, length(PStr) - 2, $.),
     STime ++ ";" ++ S ++ ";" ++ A
  end, "", NPath),

  if (Str =/= []) ->
    string:left(Str, length(Str) - 1, $.);
  true ->
    ""
  end.

sync_time_extra([], _Src, _Dst, _LNSent, _LNRecv, _Direction) ->
  {0, 0, 0};
sync_time_extra(TPShortPath, Src, Dst, LNSent, LNRecv, _Direction) ->
  PShortPath = tuple_to_list(TPShortPath),
  Send_time = get_sent_time(Src, LNSent),
  ShortPath = [X || X <- PShortPath, X =/= Src],
  {_, _, Recv_time, LastDelta, ResDiff} =
  lists:foldl(
  fun(X, {ASrc, ATime, _ARTime, _DeltaT, Res}) ->

    {_PathSrc, PathAddr, Delta, RecvTimeSync, _RecvTime} =
    lists:foldr(
    fun(XX, Tuple) ->
      case XX of
        {X, ASrc, RTimeStamp} ->
          DT = find_delta_t(ASrc, ATime, X, RTimeStamp),
          {ASrc, X, DT, RTimeStamp - DT, RTimeStamp};
        {X, ASrc, _, RTimeStamp, _} ->
          DT = find_delta_t(ASrc, ATime, X, RTimeStamp),
          {ASrc, X, DT, RTimeStamp - DT, RTimeStamp};
        _ -> Tuple
      end
    end, {ASrc, 0, 0, 0, 0}, LNRecv),

    {_SendTimeStamp, SendTimeSync} =
    lists:foldr(
    fun(XX, Tuple) ->
      case XX of
        {PathAddr, _, STimeStamp} ->
          {STimeStamp, STimeStamp - Delta};
        {PathAddr, _, STimeStamp, _} ->
          {STimeStamp, STimeStamp - Delta};
        _ -> Tuple
      end
    end, {0, 0}, LNSent),

    Diff =
    if (PathAddr == Dst) ->
      RecvTimeSync;
    true -> SendTimeSync - RecvTimeSync
    end,

    TRes =
    case Diff of
      _ when (Diff < 0) and (Res == true) -> false;
      _ when (Diff < 0) and (Res == false) -> Res;
      _ when (Res == false) -> Res;
      _ -> true
    end,

    {X, SendTimeSync, RecvTimeSync, Delta, TRes}

  end, {Src, Send_time, 0, 0, true} , ShortPath),

  MTime = (Recv_time - Send_time) / 1000000,
  {MTime, LastDelta, ResDiff}.


findPathsHelper(Src, Dst, _LNSent, SendAck, LNRecvAck, CurrPath, _Ns, [], Hops, icrpr, _EtsTable, back) ->
  % delete all without Src and Dst
  % create path from Src to Dst
  NPath = delete_no_coplete_path(Src, Dst, CurrPath),

  Length = length(NPath),
  OnePath =
  if(Length > 1) ->
    PPath =
    lists:foldr(fun(X, A)->
      TL = tuple_to_list(X),
      LengthTL = length(TL),
      HopsLLength = Hops + 2,
      case LengthTL of
        _  when (LengthTL == HopsLLength) -> [list_to_tuple(TL)];
        _ -> A
      end
    end, [], NPath),
    PPath;
  true ->
    NPath
  end,

  if OnePath == [] -> {0, 0, ""};
    true ->
    [OnePathT] = OnePath,
    {Time, Delta, _Diff} = sync_time_extra(OnePathT, Src, Dst, SendAck, LNRecvAck, back),
    {Delta, Time, path_to_str(OnePath, back)}
  end;

findPathsHelper(Src, Dst, _LNSent, _SendAck, _LNRecvAck, CurrPath, _Ns, [], _Hops, _NLProtocol, _EtsTable, back) ->
   NPath = delete_no_coplete_path(Src, Dst, CurrPath),
   {0, 0, path_to_str(NPath, back)};
findPathsHelper(Src, Dst, LNSent, _SendAck, LNRecv, CurrPath, _Ns, [], _Hops, _NLProtocol, EtsTable, direct) ->
  % delete all without Src and Dst
  % create path from Src to Dst
  NPath = delete_no_coplete_path(Src, Dst, CurrPath),

  {DT, MinTime, NewPaths} =
  lists:foldr(
  fun(Path, Tuple = {_DeltaT, MinTimeT, A}) ->
    {Time, Delta, Diff} = sync_time_extra(Path, Src, Dst, LNSent, LNRecv, direct),
    if (Diff == true) ->
      TimeT =
      if (Time < MinTimeT) -> Time; true -> MinTimeT end,
      NPL = [ {Time, Path} | A],
      {Delta, TimeT, NPL};
    true ->
      Tuple
    end
  end, {0, 100000000, []}, NPath),

  if (DT =/= 0) ->
    ets:insert(EtsTable, {{Src, Dst}, DT});
  true ->
    nothing
  end,

  Tuple =
  if(NewPaths == []) ->
    Res = ets:lookup(EtsTable, {Src, Dst}),
    DeltaS =
    case Res of
      [{ {Src, Dst}, D}] -> D;
      _ -> 0
    end,

    Send_timeL = get_sent_time_list(Src, LNSent),
    Recv_time = getTime(Dst, LNRecv, recv),
    TimeS =
    lists:foldr(
    fun(X, A) ->
      RTD = (Recv_time - DeltaS - X) / 1000000,

      if (RTD > 1) and (RTD < 100) ->
        if A == MinTime ->
          RTD;
        true ->
          if (RTD < A) and (A > 0) ->
            RTD;
          true -> A
          end
        end;
      true -> A
      end
    end, MinTime, Send_timeL),

    NewPathsT =
    lists:foldr(
    fun(X, A) ->
      [{TimeS, X} | A]
    end, [], NPath),

    {DeltaS, TimeS, path_to_str(NewPathsT, direct)};
  true ->
    {DT, MinTime, path_to_str(NewPaths, direct)}
  end,

  Tuple;

findPathsHelper(Src, Dst, LNSent, SendAck, LNRecv, CurrPath, Ns, ProcessedNs, Hops, NLProtocol, EtsTable, Direction) ->
  {TNs, TCurrPath, TProcessedNs} =
  lists:foldr(
  fun(X, {NNs, NCurrPath, NProcessedNs}) ->
    HNs = get_rcv_neighbours(X, LNRecv),

    PHNs = [XN || XN <- HNs, not lists:member(X, ProcessedNs)],
    Member = ((lists:member(X, ProcessedNs)) or (PHNs == [])),
    HCurrPath =
    if not Member -> form_path(X, PHNs, NCurrPath);
    true -> NCurrPath end,

    HProcessedNs = [X | ProcessedNs],

    {lists:flatten(NNs, PHNs),
    HCurrPath,
    lists:flatten(NProcessedNs, HProcessedNs)}
  end, {[], CurrPath, []}, Ns),

  SetTNs = sets:from_list(TNs),
  RDublNs = sets:to_list(SetTNs),

  SetTProcessedNs = sets:from_list(TProcessedNs),
  RDProcessedNs = sets:to_list(SetTProcessedNs),

  CheckNs =
  lists:foldr(
  fun(X, A) ->
    Member = lists:member(X, RDProcessedNs),
    if not Member -> false;
    true -> A
    end
  end, true, RDublNs),

  if CheckNs ->
    findPathsHelper(Src, Dst, LNSent, SendAck, LNRecv, TCurrPath, RDublNs, [], Hops, NLProtocol, EtsTable, Direction);
  true ->
    findPathsHelper(Src, Dst, LNSent, SendAck, LNRecv, TCurrPath, RDublNs, RDProcessedNs, Hops, NLProtocol, EtsTable, Direction)
  end.

get_sent_time_list(Src, LNSent) ->
  lists:foldr(
  fun(X, A) ->
    case X of
      {Src, _, Time} -> [Time | A];
      _ -> A
    end
  end, [], LNSent).

form_path(Addr, Ns, CurrentPath) ->
  CP =  lists:flatten(CurrentPath),
  lists:foldr(
  fun(X, A) ->
    TL = tuple_to_list(X),
    Member = lists:member(Addr, TL),
    if Member ->
      Path =
      lists:foldr(
      fun(N, P) ->
        NPath = [ N | TL],
        [ list_to_tuple(NPath) | P]
      end, [], Ns),
      [Path | A];
    true ->
      [X | A]
    end
  end, [], CP).

get_rcv_neighbours(Addr, List) ->
  lists:foldr(
    fun(X, A) ->
      case X of
        {Addr, NAddr, _RTimeStamp} ->
          Member = lists:member(NAddr, A),
          if(not Member) -> [ NAddr | A]; true -> A end;
        {Addr, NAddr, _, _RTimeStamp, _} ->
          Member = lists:member(NAddr, A),
          if(not Member) -> [ NAddr | A]; true -> A end;
        _ ->
          A
      end
    end, [], List).

getParams(L) ->
  Str =
  lists:foldr(
  fun(X, A) ->
    {Src, Dst, Rssi, Integrity, Velocity} = X,
    %[Src, Dst, Rssi, Integrity, Velocity | A]
    SStr = integer_to_list(Src),
    SDst = integer_to_list(Dst),
    SRssi = integer_to_list(Rssi),
    SIntegrity = integer_to_list(Integrity),
    [SVelocity] = io_lib:format("~.4f", [Velocity]),
    T = SStr ++ ";" ++ SDst ++ ";" ++ SRssi ++ ";" ++ SIntegrity ++ ";" ++ SVelocity,
    T ++ ";" ++ A
  end, "", L),

  if (Str =/= []) ->
    string:left(Str, length(Str) - 1, $.);
  true ->
    ""
  end.

getTime(Src, L, Flag) ->
  lists:foldr(
  fun(X, A) ->
    case Flag of
      {recv_src, RSrc} ->
        case X of
          {Src, RSrc, TimeRecv} ->
            TimeRecv;
          _ -> A
        end;
      send ->
        case X of
          {Src, _, TimeSent} -> TimeSent;
          _ -> A
        end;
      recv ->
        case X of
          {Src, _, TimeRecv} ->
            Min = ((A =/= 0) and (A < TimeRecv)),
            if Min -> A; true -> TimeRecv end;
          _ -> A
        end;
      recv_ack ->
        case X of
          {Src, RSrc, _, TimeRecv, Hops} ->
            Min = ((A =/= 0) and (A < TimeRecv)),
            Val = if Min -> A; true -> {TimeRecv, Hops, RSrc} end,
            Val;
          _ -> A
        end;
      send_ack ->
        case X of
          {Src, _, TimeSent, _} ->
            TimeSent;
          _ -> A
        end
    end
  end, 0, L).


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
