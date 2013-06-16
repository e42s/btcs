-module(blockchain).
-compile(export_all).

%% The first block in the blockchain contains 285 bytes.

read_network_id(Bin) ->
    %% 4 bytes
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
            error_reading_network_id
    end.

read_block_length(Bin) ->
    %% 4 bytes
    %% 2^32 bytes is about 4GB
    %% The current client will not accept blocks larger than 1MB.
    case Bin of
        <<BlockLengthBin:4/binary, Rest/binary>> ->
            <<BlockLength:32/integer-little>> = BlockLengthBin,
            {BlockLength, Rest};
        _ ->
            error_reading_block_length
    end.

read_block_format_version(Bin) ->
    %% 4 bytes
    %% This is distinct from protocol version and client version.
    case Bin of
        <<BlockFormatVersionBin:4/binary, Rest/binary>> ->
            <<BlockFormatVersion:32/integer-little>> = BlockFormatVersionBin,
            {BlockFormatVersion, Rest};
        _ ->
            error_reading_block_format_version
    end.

read_hash_of_previous_block(Bin) ->
    %% 32 bytes
    %% It is actually possible for a block to hash to zero, but hugely
    %% unlikely (though more and more likely as the difficulty
    %% increases).
    case Bin of
        <<HashOfPreviousBlockBin:32/binary, Rest/binary>> ->
            <<HashOfPreviousBlock:256/integer-little>> = HashOfPreviousBlockBin,
            {HashOfPreviousBlock, Rest};
        _ ->
            error_reading_hash_of_previous_block
    end.

go() ->
    {ok, Bin} = file:read_file("blocks/blk00000.dat"),
    {_NetworkID, Bin1} = read_network_id(Bin),
    {_BlockLength, Bin2} = read_block_length(Bin1),
    {_BlockFormatVersion, Bin3} = read_block_format_version(Bin2),
    {HashOfPreviousBlock, _Bin4} = read_hash_of_previous_block(Bin3),
    HashOfPreviousBlock.
