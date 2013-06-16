all:
	erlc -o ebin/ src/*.erl src_tests/*.erl

clean:
	rm ebin/*.beam
