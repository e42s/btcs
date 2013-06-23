-module(script).
-compile(export_all).

%% Bitcoin uses a scripting system for transactions. Forth-like,
%% Script is simple, stack-based, and processed from left to right. It
%% is purposefully not Turing-complete, with no loops.
%%
%% Scripts are big-endian. 
%% 
%% Ref:
%%   https://en.bitcoin.it/wiki/Script

go() ->
    ok.

