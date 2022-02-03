#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>

#include "helpers.h" /* TRY (assertion , description)*/
#include "parson.h" /* operatii de parsare a structurilor JSON*/

#define SERVICE "ec2-3-8-116-10.eu-west-2.compute.amazonaws.com"
#define BUFLEN 4096
#define LINELEN 1024
#define NAMELEN 64
#define PORTNO 8080
#define FLAGS 0
#define PADDING 11

#define COMPUTE_MESSAGE(mes, lin)	\
    strcat(mes, lin);				\
    strcat(mes, "\r\n")

#define PROMPTLINE(str, name)			\
    printf(name);						\
    fgets(str, NAMELEN - 1, stdin);	\
    str[strlen(str) - 1] = 0

#define CREDENTIALS(usr, psw)		\
	PROMPTLINE(usr, "username=");	\
	PROMPTLINE(psw, "password=")

#define ERRPRINTF(...)		\
	printf("\033[0;31m");	\
	printf(__VA_ARGS__);	\
	printf("\033[0m")

#define SUCCPRINTF(...)		\
	printf("\033[0;32m");	\
	printf(__VA_ARGS__);	\
	printf("\033[0m")

#define EXTRACT_JSON(a) strstr(a, "{\"") 


/*
	Obtine ip-ul serverului in network byte order
*/
uint32_t get_ip(const char *hostname) {
	struct addrinfo hints, *res;
	hints.ai_flags = FLAGS;
	hints.ai_family = AF_INET;
	hints.ai_socktype = 0;
	hints.ai_protocol = PORTNO;
	int ret = getaddrinfo(hostname, NULL, &hints, &res);
	if (ret < 0) {
		perror(gai_strerror(ret));
		freeaddrinfo(res);
		return 0;
	}
	uint32_t ip = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
	freeaddrinfo(res);
	return ip;
}

int isnumber(char *str) {
	while (*str) {
		if (*str < '0' || *str > '9') return 0;
		str++;
	}
	return 1;
}

/*
	Parsarea unei liste de carti si afisarea rezultatelor
	biblioteci externe: parson.h
*/

void print_books(const char *string) {
	JSON_Value *root_value;
    JSON_Array *keyfields;
    JSON_Object *keyvalue;
    root_value = json_parse_string(string);

    if (json_value_get_type(root_value) != JSONArray) {
    	json_value_free(root_value);
    	return;
    }
    keyfields = json_value_get_array(root_value);
    printf("\n%-*s: %s\n\n", PADDING,  "ID", "TITLE");
    for (int i = 0; i < json_array_get_count(keyfields); i++) {
		keyvalue = json_array_get_object(keyfields, i);
		printf("%-*d: %s\n", PADDING,
			(int)json_object_get_number(keyvalue, "id"),
            json_object_get_string(keyvalue, "title"));
    }
    json_value_free(root_value);
}

/*
	Parsarea datelor unei descrieri si afisarea rezultatelor
	biblioteci externe: parson.h
*/

void print_book(const char *string) {
	JSON_Value *root_value;
    JSON_Object *keyvalue;
    root_value = json_parse_string(string);

    if (json_value_get_type(root_value) != JSONObject) {
    	json_value_free(root_value);
    	return;
    }
    keyvalue = json_value_get_object(root_value);
    printf("\n%-*s: %s\n", PADDING,  "Title",
    	json_object_get_string(keyvalue, "title"));
    printf("%-*s: %s\n", PADDING,  "Author",
    	json_object_get_string(keyvalue, "author"));
    printf("%-*s: %s\n", PADDING,  "Publisher",
    	json_object_get_string(keyvalue, "publisher"));
    printf("%-*s: %s\n", PADDING,  "Genre",
    	json_object_get_string(keyvalue, "genre"));
    printf("%-*s: %d\n", PADDING,  "Page_count",
    	(int)json_object_get_number(keyvalue, "page_count"));
    json_value_free(root_value);
}

/*
	Parsarea mesajului de eroare si afisare rezultatului
	biblioteci externe: parson.h
*/

void print_server_err(const char *string) {
	JSON_Value *root_value;
    JSON_Object *keyvalue;
    root_value = json_parse_string(string);
    if (json_value_get_type(root_value) != JSONObject) {
    	json_value_free(root_value);
    	return;
    }
    keyvalue = json_value_get_object(root_value);
    ERRPRINTF("%s\n", json_object_get_string(keyvalue, "error"));
    json_value_free(root_value);
}

/*
	Prompt pentru citirea si generarea unei descrieri
*/

char *writebook(void) {
	char * book = malloc(sizeof(char) * BUFLEN);
	char line[LINELEN];
	char name[NAMELEN];
	strcpy(book, "{");

	PROMPTLINE(name, "title=");
	sprintf(line, "\"title\":\"%s\",", name);
	strcat(book, line);

	PROMPTLINE(name, "author=");
	sprintf(line, "\"author\":\"%s\",", name);
	strcat(book, line);

	PROMPTLINE(name, "publisher=");
	sprintf(line, "\"publisher\":\"%s\",", name);
	strcat(book, line);

	PROMPTLINE(name, "genre=");
	sprintf(line, "\"genre\":\"%s\",", name);
	strcat(book, line);

	PROMPTLINE(name, "page_count=");
	if (!isnumber(name)) {
		ERRPRINTF("page_count has to be a number\n");
		free(book);
		return NULL;
	}
	sprintf(line, "\"page_count\":%s", name);
	strcat(book, line);

	strcat(book, "}");
	return book;
}

/*
	Deschidearea unei conexiuni noi
*/

int open_connection(struct sockaddr_in serv_addr) {
	int sockfd;
	TRY((sockfd = socket(AF_INET, SOCK_STREAM, FLAGS)) < 0, "sockfd");
	TRY(connect(sockfd, (struct sockaddr *)&serv_addr,
    			sizeof(serv_addr)) < 0, "connect");
	return sockfd;
}

/*
	Functia formateaza diferite tipuri de crerei de exemplu GET POST DELETE
	si le transmite la server.
*/

int send_request(int sockfd, char *type, char *url, char *query_params,
				char *ctype, char **headers, int hcount, char **cookies,
				int ccount, char *body_data) {
	char message[BUFLEN] = {0};
	char line[LINELEN];

	if (query_params != NULL) {
	    sprintf(line, "%s %s/%s HTTP/1.1", type, url, query_params);
	} else {
	    sprintf(line, "%s %s HTTP/1.1", type, url);
	}
	COMPUTE_MESSAGE(message, line);

	if (headers && hcount > 0) {
		for (int i = 0 ; i < hcount ; i++) {
			sprintf(line, "%s", headers[i]);
			COMPUTE_MESSAGE(message, line);
		}
	}
	if (ctype) {
		sprintf(line, "Content-Type: %s", ctype);
		COMPUTE_MESSAGE(message, line);
		sprintf(line, "Content-Length: %ld", strlen(body_data));
		COMPUTE_MESSAGE(message, line);
	}
	if (cookies && ccount > 0) {
		sprintf(line, "Cookie: ");
		for (int i = 0; i < ccount; i++) {
			strcat(line, cookies[i]);
			if (i != ccount - 1) {
				strcat(line, ";");
			}
		}
		COMPUTE_MESSAGE(message, line);
	}
	COMPUTE_MESSAGE(message, "");
	if (body_data && ctype) {
		COMPUTE_MESSAGE(message, body_data);
	}

	return send(sockfd, message, strlen(message), 0);
}

/*
	Functia raspunde de transmiterea unui request de creare de cont
	si afisarea raspunsului primit de la server
*/

int post_register(int sockfd,  char *username, char *password) {
	if (!username || !password) return 0;
	char buf[BUFLEN] = {0};
	char *tok = NULL;

	sprintf(buf, "{\"username\":\"%s\",\"password\":\"%s\"}",
			username, password);
	send_request(sockfd, "POST", "/api/v1/tema/auth/register",
					NULL, "application/json", NULL, 0, NULL, 0, buf);
	TRY(recv(sockfd, buf, BUFLEN, 0) == 0, "timeout");

	if (!strstr(buf, "HTTP/1.1 201 Created\r\n")) {
		// caz exceptie deoarece raspunsul nu e in format json chiar daca
		// ar trebui sa fie X(
		if (strstr(buf, "HTTP/1.1 429 Too Many Requests\r\n")) {
			ERRPRINTF("Too many requests, please try again later.\n");
			return 1;
		}
		print_server_err(EXTRACT_JSON(buf));
		return 1;
	}
	SUCCPRINTF("success\n");
	return 0;
}

/*
	Functia raspunde de transmiterea unui request de logare
	si afisarea raspunsului primit de la server
*/

char *post_login(int sockfd, char *username, char *password) {
	if (!username || !password) return NULL;
	char buf[BUFLEN] = {0};
	char *tok = NULL;

	sprintf(buf, "{\"username\":\"%s\",\"password\":\"%s\"}",
				username, password);
	send_request(sockfd, "POST", "/api/v1/tema/auth/login", NULL,
					"application/json", NULL, 0, NULL, 0, buf);
	TRY(recv(sockfd, buf, BUFLEN, 0) == 0, "timeout");

	if (!strstr(buf, "HTTP/1.1 200 OK\r\n")) {
		// caz exceptie deoarece raspunsul nu e in format json chiar daca
		// ar trebui sa fie X(
		if (strstr(buf, "HTTP/1.1 429 Too Many Requests\r\n")) {
			ERRPRINTF("Too many requests, please try again later.\n");
			return NULL;
		}
		print_server_err(EXTRACT_JSON(buf));
		return NULL;
	}
	SUCCPRINTF("success\n");
	tok = strstr(buf, "Set-Cookie:");
	tok = strtok(tok, ": \r\n");
	tok = strtok(NULL, "\r\n");
	return strdup(tok);
}

/*
	Functia raspunde de transmiterea unui request de delogare
	si afisarea raspunsului primit de la server
*/

int get_logout(int sockfd, char *key) {
	if (!key) return 1;
	char buf[BUFLEN] = {0};

	send_request(sockfd, "GET", "/api/v1/tema/auth/logout",
					NULL, NULL, NULL, 0, &key, 1, NULL);
	TRY(recv(sockfd, buf, BUFLEN, 0) == 0, "timeout");
	
	if (!strstr(buf, "HTTP/1.1 200 OK\r\n")) {
		print_server_err(EXTRACT_JSON(buf));
		return 1;
	}
	SUCCPRINTF("success\n");
	return 0;
}

/*
	Functia raspunde de transmiterea unui request de access la librarie
	si afisarea raspunsului primit de la server
*/

char *get_access(int sockfd, char *key) {
	if (!key) return NULL;
	char buf[BUFLEN] = {0};
	char *tok = NULL;

	send_request(sockfd, "GET", "/api/v1/tema/library/access",
					NULL, NULL, NULL, 0, &key, 1, NULL);
	TRY(recv(sockfd, buf, BUFLEN, 0) == 0, "timeout");

	if (!strstr(buf, "HTTP/1.1 200 OK\r\n")) {
		print_server_err(EXTRACT_JSON(buf));
		return NULL;
	}
	SUCCPRINTF("success\n");
	tok = strstr(buf, "{\"token\":");
	tok = strtok(tok, ":");
	tok = strtok(NULL, "\"");
	return strdup(tok);
}

/*
	Functia raspunde de transmiterea unui request de afisare a descrierilor
	si afisarea raspunsului primit de la server
*/

char *get_books(int sockfd, char *tok) {
	if (!tok) return NULL;
	char *buf = malloc(BUFLEN * sizeof(char));

	sprintf(buf, "Authorization: Bearer %s", tok);
	send_request(sockfd, "GET", "/api/v1/tema/library/books",
					NULL, NULL, &buf, 1, NULL, 0, NULL);
	memset(buf, 0, BUFLEN);
	TRY(recv(sockfd, buf, BUFLEN, 0) == 0, "timeout");

	if (!strstr(buf, "HTTP/1.1 200 OK\r\n")) {
		print_server_err(EXTRACT_JSON(buf));
		return NULL;
	}
	print_books(strstr(buf, "[{\""));
	SUCCPRINTF("success\n");
	free(buf);
	return NULL;
}

/*
	Functia raspunde de transmiterea unui request de adaugare a unei descrieri
	si afisarea raspunsului primit de la server
*/

char *post_book(int sockfd, char *token, char *book) {
	if (!book || !token) return NULL;
	char buf[BUFLEN] = {0};
	char *tok = NULL;
	char *auth = malloc(sizeof(char ) * LINELEN);
	sprintf(auth, "Authorization: Bearer %s", token);

	send_request(sockfd, "POST", "/api/v1/tema/library/books", NULL,
					"application/json", &auth, 1, NULL, 0, book);	
	free(auth);
	TRY(recv(sockfd, buf, BUFLEN, 0) == 0, "timeout");
	if (!strstr(buf, "HTTP/1.1 200 OK\r\n")) {
		// caz exceptie deoarece raspunsul nu e in format json chiar daca
		// ar trebui sa fie X(
		if (strstr(buf, "HTTP/1.1 429 Too Many Requests\r\n")) {
			ERRPRINTF("Too many requests, please try again later.\n");
			return NULL;
		}
		print_server_err(EXTRACT_JSON(buf));
		return NULL;
	}
	SUCCPRINTF("success\n");
	return NULL;
}

/*
	Functia raspunde de transmiterea unui request de afisare a unei singure
	carti si afisarea raspunsului primit de la server
*/

char *get_book(int sockfd,  char *token, char *id) {
	if (!token) return NULL;
	char buf[BUFLEN];
	char *tok = NULL;
	char *auth = malloc(sizeof(char ) * LINELEN);
	sprintf(auth, "Authorization: Bearer %s", token);
	send_request(sockfd, "GET", "/api/v1/tema/library/books", id, NULL,
					&auth, 1, NULL, 0, NULL);	
	free(auth);
	memset(buf, 0, BUFLEN);
	TRY(recv(sockfd, buf, BUFLEN, 0) == 0, "timeout");
	if (!strstr(buf, "HTTP/1.1 200 OK\r\n")) {
		print_server_err(EXTRACT_JSON(buf));
		return NULL;
	}
	print_book(EXTRACT_JSON(buf));
	SUCCPRINTF("success\n");
	return NULL;
}

/*
	Functia raspunde de transmiterea unui request de sterger a unei singure
	cartie si afisarea raspunsului primit de la server
*/

int delete_book(int sockfd, char *token, char *id) {
	if (!token) return 1;
	char buf[BUFLEN];
	char *tok = NULL;
	char *auth = malloc(sizeof(char ) * LINELEN);
	sprintf(auth, "Authorization: Bearer %s", token);
	send_request(sockfd, "DELETE", "/api/v1/tema/library/books", id, NULL,
					&auth, 1, NULL, 0, NULL);	
	free(auth);
	memset(buf, 0, BUFLEN);
	TRY(recv(sockfd, buf, BUFLEN, 0) == 0, "timeout");
	if (!strstr(buf, "HTTP/1.1 200 OK\r\n")) {
		print_server_err(EXTRACT_JSON(buf));
		return 1;
	}
	SUCCPRINTF("success\n");
	return 0;
}

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[BUFLEN];
	char line[LINELEN];
	char username[NAMELEN];
	char password[NAMELEN];
	char *book;
	uint32_t ip;
	char *key = NULL;
	char *token = NULL;
	TRY((ip = get_ip(SERVICE)) == 0, "get ip");

	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORTNO);
    serv_addr.sin_addr.s_addr = ip;

    int sockfd;

    // in acest loop se citesc comenzile de la utilizator si se apeleaza
    // functiile coresponzatoare
	while (1) {
		memset(line, 0, LINELEN);
		fgets(line, LINELEN - 1, stdin);
		if (strlen(line) < 2) continue;
		if (strncmp(line, "register", 8) == 0) {
			if (key) {
				ERRPRINTF("logout first\n");
			} else {
				CREDENTIALS(username, password);
				sockfd = open_connection(serv_addr);
				post_register(sockfd, username, password);
				close(sockfd);
			}
		} else if (strncmp(line, "login", 5) == 0) {
			if (key) {
				ERRPRINTF("already logged in as: %s\n", username);
			} else {
				CREDENTIALS(username, password);
				sockfd = open_connection(serv_addr);
				key = post_login(sockfd, username, password);
				close(sockfd);
			}
		} else if (strncmp(line, "logout", 6) == 0){
			if (key) {
				sockfd = open_connection(serv_addr);
				if (!get_logout(sockfd, key)) {
					free(key);
					key = NULL;
					free(token);
					token = NULL;
				} else {					
					ERRPRINTF("could not log out for some goddamn reason\n");
				}
				close(sockfd);
			} else {
				ERRPRINTF("user not logged in\n");
			}
		} else if (strncmp(line, "enter_library", 13) == 0){
			if (key) {
				if (token) {
					ERRPRINTF("user %s has access to the library\n", username);
				} else {
					sockfd = open_connection(serv_addr);
					token = get_access(sockfd, key);
					close(sockfd);
				}
			} else {
				ERRPRINTF("login before accessing the library\n");
			}
		} else if (strncmp(line, "get_books", 9) == 0){
			if (key) {
				if (token) {
					sockfd = open_connection(serv_addr);
					get_books(sockfd, token);
					close(sockfd);
				} else {
					ERRPRINTF("user %s does not have access to the library\n",
								username);
				}
			} else {
				ERRPRINTF("login before accessing the library\n");
			}
		} else if (strncmp(line, "post_book", 9) == 0){
			if (key) {
				if (token) {
					book = writebook();
					if (book) {
						sockfd = open_connection(serv_addr);
						post_book(sockfd,token, book);
						close(sockfd);
					}
				} else {
					ERRPRINTF("user %s does not have access to the library\n",
								username);
				}
			} else {
				ERRPRINTF("login before accessing the library\n");
			}
		} else if (strncmp(line, "add_book", 8) == 0) {
			if (key) {
				if (token) {
					if ((book = writebook())) {
						sockfd = open_connection(serv_addr);
						post_book(sockfd, token, book);
						close(sockfd);
						free(book);
					} 
				} else {
					ERRPRINTF("user %s does not have access to the library\n",
								username);
				}
			} else {
				ERRPRINTF("login before accessing the library\n");
			}
		} else if (strncmp(line, "delete_book", 11) == 0) {
			if (key) {
				if (token) {
					PROMPTLINE(line, "id=");
					if (isnumber(line)) {
						sockfd = open_connection(serv_addr);
						delete_book(sockfd, token, line);
						close(sockfd);
					} else {
						ERRPRINTF("id has to be a number\n" );
					}
				} else {
					ERRPRINTF("user %s does not have access to the library\n",
								username);
				}
			} else {
				ERRPRINTF("login before accessing the library\n");
			}
		}  else if (strncmp(line, "get_book", 8) == 0) {
			if (key) {
				if (token) {
					PROMPTLINE(line, "id=");
					if (isnumber(line)) {
						sockfd = open_connection(serv_addr);
						get_book(sockfd, token, line);
						close(sockfd);
					} else {
						ERRPRINTF("id has to be a number\n" );
					}
				} else {
					ERRPRINTF("user %s does not have access to the library\n",
								username);
				}
			} else {
				ERRPRINTF("login before accessing the library\n");
			}
		} else if (strncmp(line, "exit", 4) == 0) {
			break;
		} else {
			ERRPRINTF("unknown command: %s", line);
		}
	}
	return EXIT_SUCCESS;
}