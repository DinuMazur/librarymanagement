build: client
client: client.c helpers.h
	gcc client.c parson.c -o client
run: client
	./client
clean: client
	rm -rf client

