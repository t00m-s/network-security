serverclient:
	gcc -Wall -Wextra -pedantic traceroute_server.c -o traceroute_server
sender:
	gcc -Wall -Wextra -pedantic traceroute_sender.c -o traceroute_sender
