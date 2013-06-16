-module(blockchain).
-compile(export_all).

%% The first block in the blockchain contains 285 bytes.

read_network_id(Bin) ->
    %% The magic network ID is sent over wire as:
    %%                   249,     190,     180,     217
    NetworkIDBin = <<16#F9:8, 16#BE:8, 16#B4:8, 16#D9:8>>,

    %% All numbers in the blockchain are represented in little-endian
    %% byte order.
    %%   Big-endian: most significant byte first (at the lowest byte address)
    %%   Little-endian: least significant byte first

    %% 0xD9B4BEF9, or 3652501241 in decimal is chosen so as to be
    %% unlikely to occur in normal data.

    case Bin of
        <<NetworkIDBin:4/binary, Rest/binary>> ->
            <<NetworkID:32/integer-little>> = NetworkIDBin,
            {NetworkID, Rest};
        _ ->
            error_getting_network_id
    end.

go() ->
    {ok, Bin} = file:read_file("blocks/blk00000.dat"),
    <<B:32/binary, _/binary>> = Bin,
    read_network_id(B).
