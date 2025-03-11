all: server
	sudo ./traceroute_server
server:
	gcc -Wall -Wextra -pedantic traceroute_server.c -o traceroute_server
sender:
	gcc -Wall -Wextra -pedantic traceroute_sender.c -o traceroute_sender
