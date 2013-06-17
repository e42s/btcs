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

read_hash_of_merkle_tree(Bin, Option) ->
    %% 32 bytes
    %% Merkle trees are binary trees of hashes.
    %% Merkle trees in bitcoin use a double SHA-256.
    %% When forming a row in the tree (other than the root of the tree),
    %% the final double-hash is duplicated to ensure that the row has
    %% an even number of hashes.
    case Bin of
        <<HashOfMerkleTreeBin:32/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {HashOfMerkleTreeBin, Rest};
                _ ->
                    error_option_unknown
            end;
        _ ->
            error_reading_hash_of_merkle_tree
    end.

read_timestamp(Bin, Option) ->
    %% 4 bytes
    %% Format: UNIX epoch time
    %% Genesis block:
    %%   1231006505
    %%   Sat, 03 Jan 2009 18:15:05 UTC
    %% Max: 2^32 -> 7th February 2106
    %%   The protocol must be upgraded before then.
    case Bin of
        <<TimestampBin:4/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {TimestampBin, Rest};
                decimal ->
                    <<Timestamp:32/integer-little>> = TimestampBin,
                    {Timestamp, Rest};
                _ ->
                    error_option_unknown
            end;
        _ ->
            error_reading_timestamp
    end.
    
read_bits(Bin, Option) ->
    %% 4 bytes (The calculated difficulty target being used for this block)
    %% The target is a 256-bit number (extremely large) that all
    %% Bitcoin clients share. The SHA-256 hash of a block's header
    %% must be lower than or equal to the current target for the block
    %% to be accepted by the network. The lower the target, the more
    %% difficult it is to generate a block.

    %% Genesis block: 486604799
    case Bin of
        <<BitsBin:4/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {BitsBin, Rest};
                decimal ->
                    <<Bits:32/integer-little>> = BitsBin,
                    {Bits, Rest}
            end;
        _ ->
            error_reading_bits
    end.

read_nonce(Bin, Option) ->
    %% 4 bytes

    %% A nonce is a random number generated during the mining
    %% process. To successfully mine a block, the header is hashed. If
    %% the resulting hash value is not less than or equal to the
    %% target, the nonce is incremented and the hash is computed
    %% again.
    case Bin of
        <<NonceBin:4/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {NonceBin, Rest};
                decimal ->
                    <<Nonce:32/integer-little>> = NonceBin,
                    {Nonce, Rest}
            end;
        _ ->
            error_reading_nonce
    end.

read_transaction_count(Bin, Option) ->
    %% Transaction count is a variable length integer representing the
    %% number of transactions in this block.

    %% A maximum of 8 bytes are available for it.
    %% Maximum number of transactions in a block: 2^64

    %% A block can never have zero transactions; at the very least
    %% there will always be one generating the block reward.

    %% Satoshi client code it refers to this as a "CompactSize".
    
    %% Encoding:
    %%   Value         Storage Length   Format
    %%   <  0xFD           1            uint8_t
    %%   <= 0xFFFF         3            0xfd followed by the length as uint16_t
    %%   <= 0xFFFFFFFF     5            0xfe followed by the length as uint32_t
    %%   -                 9            0xff followed by the length as uint64_t
    case Bin of
        <<Take1:8/integer, _/binary>> when Take1 < 16#FD ->
            read_transaction_count(Bin, Option, 1);
        <<16#FD:8/integer, _/binary>> ->
            read_transaction_count(Bin, Option, 3);
        <<16#FE:8/integer, _/binary>> ->
            read_transaction_count(Bin, Option, 5);
        <<16#FF:8/integer, _/binary>> ->
            read_transaction_count(Bin, Option, 9);
        _ ->
            error_decoding_length_of_transaction_count
    end.
read_transaction_count(Bin, Option, StorageLength) ->
    case StorageLength of
        1 ->
            case Bin of
                <<CountBin:1/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:8/integer>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_transaction_count_when_storage_length_is_1
            end;
        3 ->
            case Bin of
                <<16#FD, CountBin:2/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:16/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_transaction_count_when_storage_length_is_3
            end;
        5 ->
            case Bin of
                <<16#FE, CountBin:4/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:32/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_transaction_count_when_storage_length_is_5
            end;
        9 ->
            case Bin of
                <<16#FF, CountBin:8/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:64/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_transaction_count_when_storage_length_is_9
            end
    end.

read_transaction_version_number(Bin, Option) ->
    %% 4 bytes
    case Bin of
        <<TransactionVersionBin:4/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {TransactionVersionBin, Rest};
                decimal ->
                    <<TransactionVersion:32/integer-little>> = TransactionVersionBin,
                    {TransactionVersion, Rest}
            end;
        _ ->
            error_reading_transaction_version_number
    end.

read_input_count(Bin, Option) ->
    %% Also a variable length integer
    case Bin of
        <<Take1:8/integer, _/binary>> when Take1 < 16#FD ->
            read_input_count(Bin, Option, 1);
        <<16#FD:8/integer, _/binary>> ->
            read_input_count(Bin, Option, 3);
        <<16#FE:8/integer, _/binary>> ->
            read_input_count(Bin, Option, 5);
        <<16#FF:8/integer, _/binary>> ->
            read_input_count(Bin, Option, 9);
        _ ->
            error_decoding_length_of_transaction_count
    end.
read_input_count(Bin, Option, StorageLength) ->
    case StorageLength of
        1 ->
            case Bin of
                <<CountBin:1/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:8/integer>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_input_count_when_storage_length_is_1
            end;
        3 ->
            case Bin of
                <<16#FD, CountBin:2/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:16/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_input_count_when_storage_length_is_3
            end;
        5 ->
            case Bin of
                <<16#FE, CountBin:4/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:32/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_input_count_when_storage_length_is_5
            end;
        9 ->
            case Bin of
                <<16#FF, CountBin:8/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:64/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_input_count_when_storage_length_is_9
            end
    end.

read_hash_of_input_transaction(Bin, Option) ->
    %% 32 bytes
    case Bin of
        <<HashOfInputTXBin:32/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {HashOfInputTXBin, Rest}
            end;
        _ ->
            error_reading_hash_of_input_transaction
    end.

read_input_transaction_index(Bin, Option) ->
    %% 4 bytes
    case Bin of
        <<InputTXIndexBin:4/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {InputTXIndexBin, Rest};
                decimal ->
                    <<InputTXIndex:32/integer-little>> = InputTXIndexBin,
                    {InputTXIndex, Rest}
            end;
        _ ->
            error_reading_input_transaction_index
    end.

read_response_script_length(Bin, Option) ->
    %% Also a variable length integer
    case Bin of
        <<Take1:8/integer, _/binary>> when Take1 < 16#FD ->
            read_response_script_length(Bin, Option, 1);
        <<16#FD:8/integer, _/binary>> ->
            read_response_script_length(Bin, Option, 3);
        <<16#FE:8/integer, _/binary>> ->
            read_response_script_length(Bin, Option, 5);
        <<16#FF:8/integer, _/binary>> ->
            read_response_script_length(Bin, Option, 9);
        _ ->
            error_decoding_length_of_transaction_count
    end.
read_response_script_length(Bin, Option, StorageLength) ->
    case StorageLength of
        1 ->
            case Bin of
                <<CountBin:1/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:8/integer>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_response_script_length_when_storage_length_is_1
            end;
        3 ->
            case Bin of
                <<16#FD, CountBin:2/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:16/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_response_script_length_when_storage_length_is_3
            end;
        5 ->
            case Bin of
                <<16#FE, CountBin:4/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:32/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_response_script_length_when_storage_length_is_5
            end;
        9 ->
            case Bin of
                <<16#FF, CountBin:8/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:64/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_response_script_length_when_storage_length_is_9
            end
    end.

read_response_script(Bin, ScriptLength, Option) ->
    %% Forth script

    %% The script can be used to insert messages into the blockchain.
    %% It's a privilege of being the one to mine the block.
    case Bin of
        <<ScriptBin:ScriptLength/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {ScriptBin, Rest}
            end
    end.

read_sequence_number(Bin, Option) ->
    %% The "sequence number" supports the transaction replacement
    %% feature. The idea is that you broadcast a transaction with a
    %% lock time at some point in the future. You are then free to
    %% broadcast replacement transactions (with higher sequence
    %% numbers) until that time. If you want to lock the transaction
    %% permanently, the client will set the sequence number to
    %% 0xffffffff, the largest 4-byte integer. However, the whole
    %% transaction replacement and locking feature simply isn't used
    %% in any client yet, so all transactions are broadcast locked by
    %% default.
    case Bin of
        <<SequenceNumberBin:4/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {SequenceNumberBin, Rest}
            end
    end.

read_output_count(Bin, Option) ->
    %% Also a variable length integer
    case Bin of
        <<Take1:8/integer, _/binary>> when Take1 < 16#FD ->
            read_output_count(Bin, Option, 1);
        <<16#FD:8/integer, _/binary>> ->
            read_output_count(Bin, Option, 3);
        <<16#FE:8/integer, _/binary>> ->
            read_output_count(Bin, Option, 5);
        <<16#FF:8/integer, _/binary>> ->
            read_output_count(Bin, Option, 9);
        _ ->
            error
    end.
read_output_count(Bin, Option, StorageLength) ->
    case StorageLength of
        1 ->
            case Bin of
                <<CountBin:1/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:8/integer>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_output_count_when_storage_length_is_1
            end;
        3 ->
            case Bin of
                <<16#FD, CountBin:2/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:16/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_output_count_when_storage_length_is_3
            end;
        5 ->
            case Bin of
                <<16#FE, CountBin:4/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:32/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_output_count_when_storage_length_is_5
            end;
        9 ->
            case Bin of
                <<16#FF, CountBin:8/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:64/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_output_count_when_storage_length_is_9
            end
    end.

read_output_value(Bin, Option) ->
    %% 8 bytes
    %% It's the number of base units, as one bitcoin is 100000000 base units.

    %% This field is a fixed 8 bytes, which is what sets the maximum
    %% divisibility of a bitcoin. If a single bitcoin ever became so
    %% valuable that the granularity of individual base units became
    %% too coarse, this is the field that would need updating.
    case Bin of
        <<OutputValueBin:8/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {OutputValueBin, Rest};
                decimal ->
                    <<OutputValue:64/integer-little>> = OutputValueBin,
                    {OutputValue, Rest}
            end;
        _ ->
            error
    end.

read_pk_script_length(Bin, Option) ->
    %% Also a variable length integer
    case Bin of
        <<Take1:8/integer, _/binary>> when Take1 < 16#FD ->
            read_pk_script_length(Bin, Option, 1);
        <<16#FD:8/integer, _/binary>> ->
            read_pk_script_length(Bin, Option, 3);
        <<16#FE:8/integer, _/binary>> ->
            read_pk_script_length(Bin, Option, 5);
        <<16#FF:8/integer, _/binary>> ->
            read_pk_script_length(Bin, Option, 9);
        _ ->
            error
    end.
read_pk_script_length(Bin, Option, StorageLength) ->
    case StorageLength of
        1 ->
            case Bin of
                <<CountBin:1/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:8/integer>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_pk_script_length_when_storage_length_is_1
            end;
        3 ->
            case Bin of
                <<16#FD, CountBin:2/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:16/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_pk_script_length_when_storage_length_is_3
            end;
        5 ->
            case Bin of
                <<16#FE, CountBin:4/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:32/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_pk_script_length_when_storage_length_is_5
            end;
        9 ->
            case Bin of
                <<16#FF, CountBin:8/binary, Rest/binary>> ->
                    case Option of
                        raw -> {CountBin, Rest};
                        decimal -> <<Count:64/integer-little>> = CountBin, {Count, Rest}
                    end;
                _ ->
                    error_reading_pk_script_length_when_storage_length_is_9
            end
    end.

read_pk_script(Bin, ScriptLength, Option) ->
    %% Satoshi's first Bitcoin address:
    %%   1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    
    case Bin of
        <<ScriptBin:ScriptLength/binary, Rest/binary>> ->
            case Option of
                raw ->
                    {ScriptBin, Rest}
            end
    end.

go() ->
    {ok, Bin} = file:read_file("blocks/blk00000.dat"),
    {_NetworkID,           Bin1} = read_network_id(Bin),
    {_BlockLength,         Bin2} = read_block_length(Bin1),
    {_BlockFormatVersion,  Bin3} = read_block_format_version(Bin2),
    {_HashOfPreviousBlock, Bin4} = read_hash_of_previous_block(Bin3),
    {_HashOfMerkleTree,    Bin5} = read_hash_of_merkle_tree(Bin4, raw),
    {_TS,                  Bin6} = read_timestamp(Bin5, decimal),
    {_Bits,                Bin7} = read_bits(Bin6, decimal),
    {_NonceBin,            Bin8} = read_nonce(Bin7, raw),
    {_TransactionCount,     Bin9} = read_transaction_count(Bin8, decimal),
    {_TVN,                  Bin10} = read_transaction_version_number(Bin9, decimal),
    {_IC,            Bin11} = read_input_count(Bin10, decimal),
    {_HashOfInputTXBin, Bin12} = read_hash_of_input_transaction(Bin11, raw),
    {_ITI, Bin13} = read_input_transaction_index(Bin12, raw),
    {RSL, Bin14} = read_response_script_length(Bin13, decimal),
    {_ScriptBin, Bin15} = read_response_script(Bin14, RSL, raw),
    {_SequenceNumberBin, Bin16} = read_sequence_number(Bin15, raw),
    {_OutputCount, Bin17} = read_output_count(Bin16, decimal),
    {_OutputValue, Bin18} = read_output_value(Bin17, decimal),
    {PKL, Bin19} = read_pk_script_length(Bin18, decimal),
    {PKSBin, _Bin20} = read_pk_script(Bin19, PKL, raw),
    binary_to_hex_string(PKSBin).


binary_to_hex_string(Bin) ->
    lists:flatten([io_lib:format("~2.16.0B",[X]) || <<X:8>> <= Bin ]).
