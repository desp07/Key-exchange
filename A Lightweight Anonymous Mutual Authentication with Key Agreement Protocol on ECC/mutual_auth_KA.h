#ifndef LAMA_SERVER_CLIENTH
#define LAMA_SERVER_CLIENTH

#include<stdlib.h>

//The header file that describes the functionality of the lama_server_client.c file

typedef struct dr{
	char ID[4];
	unsigned char AID[33];
	unsigned char next_AID[33];
	unsigned char Dc_str_1[80];
	unsigned char Dc_str_2[80];
	size_t dc_size1;
	size_t dc_size2;
}data_received;

const char* getfield(char* line, int num);

void InitializeSSL();

void DestroySSL();

void ShutdownSSL();

int client_register(data_received* ID_client); 

void lama_server();

void lama_client(data_received* ID_client);


#endif

