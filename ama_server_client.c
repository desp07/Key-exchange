#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h> 
#include <sys/poll.h>
#include <arpa/inet.h>
#include <tomcrypt.h>
#include <gmp.h>
#include "lama_server_client.h"
#include <errno.h>
#define MAX 100


gmp_randstate_t stat; 


const char* getfield(char* line, int num)
{
    const char* tok;
    tok = strtok(line, ",");
    int i = 1;
    while (tok != NULL){
    	printf("%s\n", tok);
        //tok && *tok;
        tok = strtok(NULL, ",");
    
    	if (i == num)
        	return tok;
    }
 	return NULL;
}


void lama_server(){
	
    mpz_t p, m, n, seed, h;
    mpz_t curv[2], base_point[2];
    mpz_t randp[2];
    mpz_t randPs[2];
    mpz_t Dc[2], tc, temp1, temp2, hc;
    mpz_t L[2], Ls[2], Rtonos[2], temp3[2], R[2];
    mpz_t x;
    mpz_t temp4, temp7;
    mpf_t temp6, temp8, tc_float;
    prng_state prng;
    FILE *param_fd, *clientfd_q, *clientfd_s;
    struct sockaddr_in serv_addr, cli_addr;
    int sockfd, sockfd1, newsockfd, newsockfd1, Dc_size1, Dc_size2, hmac_err, ssl_err, err;
    socklen_t clilen;
    unsigned long temp;
    int idx, cli_found=-1, bytes, point = 0, collision = 0;
    int rbytes, dstlen;
    unsigned char IDbuffer[3], cl_hmac[32], tc_buffer[100], hash_ci[32], *t1, t2[32], *temp5;
    unsigned char cl_AID[33];
    unsigned char  ID_hashed[32], time_hashed[32], h3_str[160], ID_mac[32], time_mac[32], Rstr_mac1[32], Rstr_mac2[32], server_time_hashed[32];
    unsigned char hmac_res[32], hmac_str[96], Lstr_mac_0[32], *Dc_str[2], Lstr_mac_1[32];
    unsigned char buffer_u[32], rs, temp_hmac[32];
    unsigned char *R_str[2], *temp_mac, Rstr_hashed[32], Rtstr_hashed_0[32], Rtstr_hashed_1[32], *Ls_str_0, *Ls_str_1, *check_str, result[32], L_hashed_0[32], L_hashed_1[32], Ls_hashed_0[32], Ls_hashed_1[32];
    unsigned char *h4_str, shared_key[32], *L_str_0, *L_str_1, k[32], *Rt_str[2], *Rcomb,  random_x, time_str_u[10] ;
    char buffer[4];
    hash_state md;
    hmac_state hmac;
    size_t size_R1, size_R2, temp_size, size;
    long D, sd=0;
    struct sockaddr_in saiServerAddress, saiServerAddress1;
    unsigned long M1_time, M2_time, cl_time, dt, DT = 5;  //TODO: check whether the DT value is correct
    struct tm result_time; //variables for safe conversion of server timestamp
    unsigned char stime[32], time_str[10], AID[33];

	


    gmp_randinit_lc_2exp_size(stat, 30); //gmp_randinit, used inECCLIB, is obsolete
    //gmp_randinit(stat, GMP_RAND_ALG_LC, 120);
    /*-----------------------------------------------------------

    Initialize state for a linear congruential algorithm as per g
    mp_randinit_lc_2exp. a,c and m2exp are selected from a table, 
    chosen so that size bits (or more) 
    f each X will be used, i.e. m2exp/2 >= size.

	If successful the return value is non-zero. If size is bigger 
	than the table data provides then the return value is zero. 
	The maximum size currently supported is 128. 
    -------------------------------------------------------------*/
    const int precision = 1024;
    mpf_set_default_prec(precision); //set floating point precision to 128

    sd=0; 
    mpz_init(p);
    mpz_init(m);
    mpz_init(n);
    mpz_init(h);
    mpz_init(x);
    mpz_init(seed);
    mpz_init(curv[0]); mpz_init(curv[1]);
    mpz_init(base_point[0]); mpz_init(base_point[1]);
    mpz_init(randp[0]); mpz_init(randp[1]);
    mpz_init(randPs[0]); mpz_init(randPs[1]);
    mpz_init(tc); mpz_init(temp1); mpz_init(temp2);
    mpz_init(hc);
    mpz_init(Dc[0]); mpz_init(Dc[1]);
    mpz_init(Rtonos[0]); mpz_init(Rtonos[1]); 
    mpz_init(temp3[0]); mpz_init(temp3[1]);
    mpz_init(R[0]); mpz_init(R[1]);
    mpz_init(L[0]); mpz_init(L[1]);
    mpz_init(Ls[0]); mpz_init(Ls[1]);
    mpz_init(temp4); mpf_init(temp6);
    mpz_init(temp7); mpf_init(temp8);
    mpf_init(tc_float);

    struct record{
		unsigned char AID[33];
		//client ID could be a PLC serial number or MAC address
		char ID[4];
		long tc;
		char *Dc_str[2];
		unsigned char next_AID[33];
	}client;

	struct initialization_msg {
		unsigned char ID[4];
		unsigned long tc;
	} init_msg;

	/*struct client_data{
		unsigned char AID[33];
		
	} client_ID_data;*/

	//----------------------- random seed initialization ----------------------------------------------------------------------------------------------

    int fd = fopen("/dev/urandom", "r");//initialize the seed for the random generator using /dev/urandom
    read(fd, buffer_u, 32);
    printf("/dev/urandom number: %s\n", buffer_u);

	if ((err = fortuna_start(&prng)) != CRYPT_OK) {
		printf("Start error: %s\n", error_to_string(err));
	}
	/* add entropy */
	if ((err = fortuna_add_entropy(buffer_u, 32, &prng))!= CRYPT_OK) {
		printf("Add_entropy error: %s\n", error_to_string(err));
	}
	/* ready state*/
	if ((err = fortuna_ready(&prng)) != CRYPT_OK) {
		printf("Ready error: %s\n", error_to_string(err));
	}

	printf("Read %lu bytes from fortuna. The random array generated is: \n",fortuna_read(buffer, sizeof(buffer), &prng));	// reads a 4 byte char array from fortuna prng
	for(int i=0; i<strlen(buffer); i++){
		printf("%u", buffer[i]);	
	}
	printf("\n");
	
	//sd = (long)buffer[0]|(long)buffer[1]|(long)buffer[2]|(long)buffer[3]; //convert the charecters generated by fortuna to long integers 
	sd = (long) buffer;
	printf("sd = %ld\n",sd );
	mpz_set_ui(seed, sd);
    gmp_randseed(stat, seed); //random state seeding
    //-------------------------------------------------------------------------------------------------------------------------------------------------------------

    //----------------------------------------------- Elliptic Curve parameters & random x generation--------------------------------------------------------------
    D=40; //set a value for the discriminant of the curve

    CMmethod(D, &p, &m, curv);// generating the ECC parameters using the complex multiplication method
    domain_parameters(curv, base_point, &p, &m, &n, &h); // generate the public parameters of the elliptic curve to be used by the devices
    gmp_printf("Domain parmaters created curv = %Zd %Zd\n base_point = %Zd %Zd\n p = %Zd\n m = %Zd\n n = %Zd\n h = %Zd\n", curv[0], curv[1], base_point[0], base_point[1], p, m, n, h);
    //create_priv_and_public(curv, &p, base_point, &private_key, public_key); 

    fortuna_read(&random_x, 1, &prng); // random value x
    mpz_set_ui(x, &random_x);
    gmp_printf("Random number x: %Zd\n", x); 
    //printf("sizeof base point = %d, %d\n", mpz_sizeinbase(base_point[0], 10)+2, mpz_sizeinbase(base_point[1], 2)+2);

    myzmulmod(&randPs[0], &base_point[0], &x, &m); // Ps = x * P (P is the base point of the curve)
    myzmulmod(&randPs[1], &base_point[1], &x, &m);

    /* For the initial implementation of the algorithm the hash and mac functions will be predefined, thus the server will not send any information
    about those functions during the initialization phase*/

    param_fd=fopen("pfile.txt", "w");
    gmp_fprintf(param_fd, "%Zd %Zd %Zd %Zd %Zd %Zd %Zd %Zd", curv[0], curv[1], p, base_point[0], base_point[1], randPs[0], randPs[1], &m);
    //printf("size of m %d\n", mpz_sizeinbase(m, 10));
 
    fclose(param_fd);


//--------------------------------- Client registation phase-----------------------------------------------------------------------------------//

    sockfd1 = socket(AF_INET, SOCK_STREAM, 0);
	//sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sockfd1 < 0){ 
        printf("Error opening socket\n");
        return -1;
    }

    bzero((char *) &saiServerAddress1, sizeof(saiServerAddress1));
	// zero out the struct

	saiServerAddress1.sin_family = AF_INET;
	saiServerAddress1.sin_port = htons(1505);
	saiServerAddress1.sin_addr.s_addr = INADDR_ANY;
	//saiServerAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
 	memset(saiServerAddress1.sin_zero, '\0', sizeof(saiServerAddress1.sin_zero)); 
 	printf("PORT - %d\n", saiServerAddress1.sin_port);
	int on = 1;
    int res = setsockopt(sockfd1, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	//setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof (on));
	if(bind(sockfd1, (struct sockaddr*) &saiServerAddress1, sizeof(struct sockaddr_in))<0){
		perror("Error on binding\n");
		printf("%s %d\n", strerror(errno), errno);
        return -1;
	}

	if((listen(sockfd1, 1))==0)
		printf("Listening...\n");
    else {
        printf("Listen error: %s\n", strerror(errno));
        return -1;
    }
    clilen = sizeof(cli_addr);
	if((newsockfd1 = accept(sockfd1, (struct sockaddr *)&cli_addr, &clilen)) < 0)
		perror("Error accepting\n");

	bytes = recv(newsockfd1, &init_msg, sizeof(init_msg), 0);
	if(bytes<= 0){
        printf("Error receiving init_msg, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received init_msg- size = %ld bytes\n", bytes);

    printf("Received initialization message\n ID: ");
    for(int i=0; i<strlen(init_msg.ID); i++) printf("%c ", init_msg.ID[i]);
    printf("\nRandom tc number: %u\n", init_msg.tc);

  

//register the 4 hash functions in the hash descriptor table
	if (register_hash(&keccak_256_desc) == -1) {
		printf("Error registering keccak.\n");
	return -1;
	}

	if (register_hash(&sha256_desc) == -1) {
		printf("Error registering SHA256.\n");
	return -1;
	}

	if (register_hash(&sha3_256_desc) == -1) {
		printf("Error registering SHA3.\n");
	return -1;
	}

	if (register_hash(&blake2b_256_desc) == -1) {
		printf("Error registering BLAKE2B.\n");
	return -1;
	}

//------------------------------------calculate the hash value of the client's ID
	printf("Hash client ID using keccak256 hash function...\n");
/* get hash index */
	idx = find_hash("keccak256");
	if (idx == -1) {
		printf("Invalid hash name!\n");
		return;
	}

	hash_descriptor[idx].init(&md);//initialize the keccak 256 hash function

	hash_descriptor[idx].process(&md, init_msg.ID, strlen(init_msg.ID)); // produce the hashed IDci

	hash_descriptor[idx].done(&md, &hash_ci); //copy the produced value to hash_ci

	mpz_set_ui(tc, init_msg.tc);
	gmp_printf("tc = %Zd\n", tc);
	printf("size of tc = %d\n", sizeof(init_msg.tc));
	temp = (unsigned long)hash_ci; //TODO: check if this conversion is suitable or introduces an error
	printf("size of hash_ci: %d\n", sizeof(hash_ci));
	printf("temp %ld\n", temp);

	mpz_set_ui(hc, temp);
	printf(" hash_ci: %u\n", hash_ci);
	gmp_printf("hc: %Zd\n", hc);

	printf("DBG set str here \n");
	mpz_mul(&temp1, &x, &hc); //temp1 = x*hcmodm
	printf("DBG after mul here \n");
	gmp_printf(" temp1 = %Zd\n", temp1);
	//temp = mpz_get_ui(tc);
	gmp_printf("Computing tc/x*hci =  %Zd / %Zd\n", tc, temp1);
	mpz_cdiv_q(&temp7, &tc, &temp1);// tc/x*hc - TODO: check if the remainder that is only kept is correct approach
	gmp_printf("DBG after div and mul here %Zd\n", temp7);
	myzmulmod(&Dc[0], &temp7, &base_point[0], &m);
	gmp_printf("DBG after mul here \n");
	myzmulmod(&Dc[1], &temp7, &base_point[1], &m);
	gmp_printf("DBG after mul here \n");
	gmp_printf("Dc[0] = %Zd, Dc[1] = %Zd\n", Dc[0], Dc[1]);

	Dc_size1 = mpz_sizeinbase(Dc[0], 10)+2;
	printf("Dc_size %d\n", Dc_size1);
	client.Dc_str[0] = malloc(Dc_size1*sizeof(char));
	Dc_str[0] = malloc(Dc_size1*sizeof(char));
	Dc_size2 = mpz_sizeinbase(Dc[1], 10)+2;
	client.Dc_str[1] = malloc(Dc_size2*sizeof(char));
	Dc_str[1] = malloc(Dc_size2*sizeof(char));

	mpz_get_str(client.Dc_str[0], 0, Dc[0]);
	mpz_get_str(client.Dc_str[1], 0, Dc[1]);
	mpz_get_str(Dc_str[0], 0, Dc[0]);
	mpz_get_str(Dc_str[1], 0, Dc[1]);


	printf("strlen: %d\n", strlen(client.Dc_str[0]));
	printf("client.Dc_str[1]: %s\n", client.Dc_str[1]);
	printf("Dc_str[0] size = %u\n", sizeof(Dc_str[0]));
	printf("Dc_str[1] size = %u\n", sizeof(Dc_str[1]));
	//--------------------------------------- calculate anonymous ID--------------------------------------//
	printf("Calculating anonymous ID\n");

	t1 = malloc(sizeof(init_msg.ID)+sizeof(init_msg.tc));
	strcpy(t1 ,init_msg.ID); // ---------------------------------- IDci | tci
	printf("sizeof t1 = %d\n", strlen(t1));
	temp5 = (unsigned char*)malloc(sizeof(unsigned char)*sizeof(init_msg.tc));
	snprintf(temp5, 10, "%d",init_msg.tc); 
	strcat(t1, temp5); //TODO: check if this concatenation with unsigned char array is correct
	printf("sizeof t1 = %d\n", strlen(t1));

	printf("IDci | tci: %s\n", t1);

	idx = find_hash("sha256");
	if (idx == -1) {
	printf("Invalid hash name!\n");
	return -1;
	}

//--------------------------------------------------------- H2(IDci | tci)-----------------------------------

	printf("Calculating H2(IDci | tci)\n");

	hash_descriptor[idx].init(&md);//initialize the sha 256 hash function

	hash_descriptor[idx].process(&md, t1, strlen(t1)); // produce the hashed IDci

	hash_descriptor[idx].done(&md, &t2); //copy the produced value to t2
	//printf("H2(IDci | tci): %s\n", t2);

	printf("H2(IDci | tci): ");
	for (int i=0; i<sizeof(t2); i++)
  	{	
    	printf("%u ",t2[i]);
  	}

	printf("\nClient anonymous ID: ");
	for (int i=0; i<sizeof(client.AID); i++)
  	{	
  		unsigned char y = t2[i];
    	unsigned char temp = init_msg.ID[i] ^ y;
    	client.AID[i] = temp;
    	AID[i] = temp;

    	printf("%u ",AID[i]);
  	}
  	client.AID[32] = '\0';
  	AID[32] = '\0';
  	printf("\n\n");
  	int test = atoi(client.AID);

  	printf("Checking the client database... \n"); // checking the client database for collisions with the generated AID
  	//clientfd_q = fopen("client_db.csv", "r");
  	clientfd_s = fopen("client_db.csv", "a+"); //TODO: fix segfault on file containing only a newline
  	if(clientfd_s== NULL) printf("Error opening file\n");

	while(cli_found == -1){

    	char line[1024];
    	if(fgets(line, 150, clientfd_s)!=NULL){ //Until EOF is reached. TODO: check buffer size
    		int i=0;
   			char* tmp = strtok(line,"-");
   			while(i<32){
   				int num = atoi(tmp);

   				if(num == client.AID[i]) printf("Correct!! \n");
   				else break;
   				tmp = strtok(NULL,"-");
   				i++;
   				if(i==32) cli_found=1;

		       	printf("AID : %s\n", client.AID );
	    		
	       		char* tmp1 = strtok(NULL,",");
	       		strcpy(client.ID, tmp1);
	       		//printf("ID: %s\n", client.ID );
	       		char* tmp2 = strtok(NULL,"\n");
	       		int tmp3 = atoi(tmp2);
	       		client.tc = tmp3;
	    
   			}
   			continue;
   		}else{ //EOF 

			cli_found = 0;
			printf("Recording the new information\n");
			fflush(clientfd_s);
			//written = fprintf(clientfd_s, "%s,%s,%d\n", client.AID, init_msg.ID, init_msg.tc); //record the details of the client
			for(int i=0; i<strlen(client.AID); i++){
				fprintf(clientfd_s, "%u", client.AID[i]);
				fprintf(clientfd_s, "-");
			}

			fprintf(clientfd_s, ",");
			for(int i=0; i<4; i++){
				fprintf(clientfd_s, "%c", init_msg.ID[i]);
				printf("%u", init_msg.ID[i]);
			}

			fprintf(clientfd_s, ",%u\n", init_msg.tc);
		}

		bytes = send(newsockfd1, &Dc_size1, sizeof(Dc_size1), 0);
		if(bytes<= 0){
        	printf("Error sending first size parameter, %s\n", strerror(errno));
       		exit(-1);
    	}else printf("Sent first size parameter = %ld bytes\n", bytes);

		bytes = send(newsockfd1, &Dc_size2, sizeof(Dc_size2), 0);
		if(bytes<= 0){
        	printf("Error sending second size parameter, %s\n", strerror(errno));
       		exit(-1);
    	}else printf("Sent second size parameter = %ld bytes\n", bytes);

		bytes = write(newsockfd1, AID, sizeof(AID));
		if(bytes<= 0){
        	printf("Error sending client_ID AID, %s\n", strerror(errno));
       		exit(-1);
    	}else printf("Sent client_ID AID- size = %ld bytes\n", bytes);

    	bytes = send(newsockfd1, Dc_str[0], Dc_size1, 0);
		if(bytes<= 0){
        	printf("Error sending client_ID.Dc_str[0], %s\n", strerror(errno));
       		exit(-1);
    	}else printf("Sent client_ID.Dc_str[0] = %s - size = %ld bytes\n", Dc_str[0], bytes);

    	bytes = send(newsockfd1, Dc_str[1], Dc_size2, 0);
		if(bytes<= 0){
        	printf("Error sending client_ID.Dc_str[1], %s\n", strerror(errno));
       		exit(-1);
    	}else printf("Sent client_ID.Dc_str[1] = %s - size = %ld bytes\n", Dc_str[1], bytes);

		break;
		fflush(clientfd_s);
	} 

	fclose(clientfd_s);

//----------------------------------Authentication Phase------------------------------------------//
printf("Beginning authentication and listening for connections...\n");

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	//sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sockfd < 0){ 
        printf("Error opening socket\n");
        return -1;
    }

    bzero((char *) &saiServerAddress, sizeof(saiServerAddress));
	// zero out the struct

	saiServerAddress.sin_family = AF_INET;
	saiServerAddress.sin_port = htons(1506);
	saiServerAddress.sin_addr.s_addr = INADDR_ANY;
	saiServerAddress.sin_port = htons(1506);
 	memset(saiServerAddress.sin_zero, '\0', sizeof(saiServerAddress.sin_zero)); 
 	printf("PORT - %d\n", saiServerAddress.sin_port);
	on = 1;
    res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	//setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof (on));
	if(bind(sockfd, (struct sockaddr*) &saiServerAddress, sizeof(struct sockaddr_in))<0){
		perror("Error on binding\n");
		printf("%s %d\n", strerror(errno), errno);
        return -1;
	}

	if((listen(sockfd, 1))==0)
		printf("Listening...\n");
    else {
        printf("Listen error: %s\n", strerror(errno));
        return -1;
    }
    clilen = sizeof(cli_addr);
	if((newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen)) < 0)
		perror("Error accepting\n");
//---------------------------------------receive M1 from the client----------------------------------------------------
	bytes = recv(newsockfd, &size_R1, sizeof(size_t), 0);
	if(bytes<= 0){
        printf("Error receiving first size parameter, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received size - size = %ld bytes\n", bytes);
    printf("size_R1 = %d\n", size_R1);

    bytes = recv(newsockfd, &size_R2, sizeof(size_t), 0);
	if(bytes<= 0){
        printf("Error receiving second size parameter, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received size - size = %ld bytes\n", bytes);
    printf("size_R2 = %d\n", size_R2);

    R_str[0] = (unsigned char*)malloc(size_R1*sizeof(unsigned char));
    R_str[1] = (unsigned char*)malloc(size_R2*sizeof(unsigned char));

	bytes = recv(newsockfd, cl_AID, sizeof(cl_AID), 0);
	if(bytes<= 0){
        printf("Error receiving the anonymous ID, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received AID - size = %ld bytes\n", bytes);

    for(int i=0; i<33; i++) printf("%u ", cl_AID[i]);
    printf("\n");

    bytes = recv(newsockfd, &cl_time, sizeof(unsigned long), 0);
	if(bytes<= 0){
        printf("Error receiving the current timestamp, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received Tc - size = %ld bytes\n", bytes);

    bytes = recv(newsockfd, R_str[0], size_R1, 0);
	if(bytes<= 0){
        printf("Error receiving R[0], %s\n", strerror(errno));
        exit(-1);
    }else printf("Received R[0] - size = %ld bytes\n", bytes);
    R_str[0][bytes-1] = '\0';

    bytes = recv(newsockfd, R_str[1], size_R2, 0);
	if(bytes<= 0){
        printf("Error receiving R[1], %s\n", strerror(errno));
        exit(-1);
    }else printf("Received R[1] - size = %ld bytes\n", bytes);
    R_str[1][bytes-1] = '\0';

    //-----------------DEBUG-----------------------------------
    printf("R[0] = %s\nR[1] = %s\n", R_str[0], R_str[1] );
    //---------------------------------------------------------

    bytes = recv(newsockfd, cl_hmac, 32*sizeof(char), 0);
	if(bytes<= 0){
        printf("Error receiving the HMAC result, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received HMAC result - size = %ld bytes\n", bytes);

    printf("cl_hmac:");
    for(int i=0; i<strlen(cl_hmac); i++){
    	printf(" %u", cl_hmac[i]);
    	temp_hmac[i] = cl_hmac[i];
 	}
    printf("\n");

    // check validity of IDc and time freshness of message
    printf("Checking validity and freshness of message M1\n");

    clientfd_s = fopen("client_db.csv", "a+");
  	if(clientfd_s== NULL) printf("Error opening file\n");
    printf("----- Performing validity check -----\n");
    char line[1024];
    cli_found=-1;
   	while(fgets(line, 150, clientfd_s)!=NULL){ //Read until EOF. TODO: check buffer size
   		//printf("Read line\n");
   		int i=0;
   		char* tmp = strtok(line,"-");
   		while(i<32){
   			int num = atoi(tmp);
   			//printf("num = %d\n", num);
   			if(num == client.AID[i]) printf("Correct!! \n");
   			else break;
   			tmp = strtok(NULL,"-");
   			i++;
		}
		if(i==32) { //the client that needs to authenticate is registered - continue with timeliness check
   			cli_found=1;
	       	printf("AID : %s\n", client.AID );
			printf("cl_AID[0]: %u\n", cl_AID[0]);
   			printf("Validity check successful\n----- Performing time freshness check -----\n");


   			M1_time = time(NULL);
			sprintf(time_str, "%d", M1_time);
	   	 	
			printf("M1 received at: %s seconds\n", time_str);
			printf("Timestamp received from client = %lu\n", cl_time);
//------------------time freshness check----------------------------------------------
			dt = atoi(time_str) - cl_time; // T' - Tc
			if(dt > DT){ // T' - Tc <= Δτ
				printf("Time freshness check failed, exiting...\n");
				fclose(clientfd_s);
				exit(-1);
			}else{
				printf("Time freshness check successful\n");
				break;
			}
   				break;
   		}else{
   			continue;
		}
		if(cli_found == -1){
   			printf("Validity of the client could not be confirmed, exiting..\n");
   			fclose(clientfd_s);
   			exit(-1);
   		}
	} 
	fclose(clientfd_s);

	if(point>=1){
		printf("Validity and freshness checks failed. Aborting authentication\n");
		return;
	}
	
		//----------------------------------hci = H1(IDc)
		printf("hci = H1(IDc)\n");
		/* get hash index */
		idx = find_hash("keccak256");
		if (idx == -1) {
			printf("Invalid hash name!\n");
			return;
		}

		hash_descriptor[idx].init(&md);//initialize the RMD 256 hash function
		hash_descriptor[idx].process(&md, client.ID, strlen(client.ID)); // produce the hashed IDci
		hash_descriptor[idx].done(&md, &hash_ci); //copy the produced value to hash_ci

		printf("H1(IDci) = %s\n", hash_ci);

		//-----------------------------------------R' = (tci/x*hci)*P + R---------------------------------------------

		printf("R' = (tci/x*hci)*P + R\n");

		mpz_set_str(hc, hash_ci, 10);
		mpz_set_str(R[0], R_str[0], 10);
		mpz_set_str(R[1], R_str[1], 10);
		gmp_printf("Converted R[0] = %Zd, R[1] = %Zd\n", R[0], R[1]);

		mpz_mul(&temp1, &hc, &x); //x*hci
		mpz_cdiv_q(&temp2, &tc, &temp1); // tci/x*hci
		myzmulmod(&temp3[0], &temp2, &base_point[0], &m); //tci/x*hci *P
		myzmulmod(&temp3[1], &temp2, &base_point[1], &m);
		myzaddmod(&Rtonos[0], &temp3[0], &R[0], &m); // tci/x*hci*P + R
		myzaddmod(&Rtonos[1], &temp3[1], &R[1], &m);

		gmp_printf("Rtonos[0] = %Zd\n", Rtonos[0]);
		gmp_printf("Rtonos[1] = %Zd\n", Rtonos[1]);

		//--------------------------------------------k = H3(IDc, Tc, R, R') w/diy hash list--------------------------------------
	
		printf("k = H3(IDc, Tc, R, R')\n");
		idx = find_hash("sha3-256");	
		if (idx == -1) {
			printf("Invalid hash name!\n");
		return;
		}

		size = mpz_sizeinbase(Rtonos[0], 10);
		Rt_str[0] = (unsigned char*)malloc(size*sizeof(unsigned char));
		size = mpz_sizeinbase(Rtonos[1], 10);
		Rt_str[1] = malloc(size*sizeof(char));

		mpz_get_str(Rt_str[0], 10, Rtonos[0]);
		mpz_get_str(Rt_str[1], 10, Rtonos[1]);

		printf("Rt_str[0] = %s\n", Rt_str[0]);
		printf("Rt_str[1] = %s\n", Rt_str[1]);
		
		Rcomb = (char *)malloc((size_R2+size_R1)*sizeof(char));
		strcpy(Rcomb, R_str[0]);
		strcat(Rcomb, R_str[1]);
		size_R2 = strlen(Rcomb);
		Rcomb[size_R2-1] = '\0';

		hash_descriptor[idx].init(&md);//initialize the SHA3 256 hash function

		printf("1 - client.ID = %s\n", init_msg.ID);
		for(int i=0; i<strlen(init_msg.ID); i++) printf("%u ", init_msg.ID[i]);
		printf("\n");
		hash_descriptor[idx].process(&md, init_msg.ID, sizeof(init_msg.ID)); // produce the hashed IDci
		hash_descriptor[idx].done(&md, ID_hashed); 

		printf("ID_hashed length= %d | ", sizeof(ID_hashed));
		for(int i=0; i<sizeof(ID_hashed); i++) printf("%u ", ID_hashed[i]);
		ID_hashed[31] = '\0';
		printf("\n");

		size_R2 = strlen(R_str[1]);
		printf("%d\n", size_R2);
		R_str[1][size_R2 - 1] = '\0';

		const int n1 = snprintf(NULL, 0, "%lu", cl_time);
		assert(n1 > 0);
		char buf[n1+1];
		int c = snprintf(buf, n1+1, "%lu", cl_time);
		assert(buf[n1] == '\0');
		assert(c == n1);

		printf("2 - cl_time = %s\n", buf);

		hash_descriptor[idx].process(&md, buf, sizeof(buf));
		hash_descriptor[idx].done(&md, time_hashed); 
		time_hashed[31]='\0';
		printf("time_hashed size = %d | time_hashed length = %d", sizeof(time_hashed), strlen(time_hashed));
		for(int i=0; i<sizeof(time_hashed); i++) printf("%u ", time_hashed[i]);
		time_hashed[31] = '\0';
		printf("\n");

		printf("3 - Rcomb = %s\n", Rcomb);
		hash_descriptor[idx].process(&md, Rcomb, sizeof(Rcomb));
		hash_descriptor[idx].done(&md, Rstr_hashed);
		printf("Rstr_hashed = ");
		for(int i=0; i<sizeof(Rstr_hashed); i++) printf("%u ", Rstr_hashed[i]);
		Rstr_hashed[31] = '\0';
		printf("\n");

		printf("4 - Rt_str[0] = %s\n", Rt_str[0]);
		hash_descriptor[idx].process(&md, Rt_str[0], sizeof(Rt_str[0]));
		hash_descriptor[idx].done(&md, Rtstr_hashed_0); 
		printf("Rtstr_hashed[0] = ");
		for(int i=0; i<sizeof(Rtstr_hashed_0); i++) printf("%u ", Rtstr_hashed_0[i]);
		Rtstr_hashed_0[31] = '\0';
		printf("\n");

		printf("5 - Rt_str[1] = %s\n", Rt_str[1]);
		hash_descriptor[idx].process(&md, Rt_str[1], sizeof(Rt_str[1]));
		hash_descriptor[idx].done(&md, Rtstr_hashed_1); 
		printf("Rtstr_hashed[1] = ");
		for(int i=0; i<sizeof(Rtstr_hashed_1); i++) printf("%u ", Rtstr_hashed_1[i]);
		Rtstr_hashed_1[31] = '\0';
		printf("\n");
	

		temp_size = sizeof(ID_hashed)+ sizeof(time_hashed) + sizeof(&Rstr_hashed[0]) + sizeof(Rtstr_hashed_0) + sizeof(Rtstr_hashed_1);
		printf("temp size = %d\n", temp_size);

		printf("passed memory allocation h3_str size = %d\n", sizeof(h3_str));
		snprintf(h3_str, 160*sizeof(char),"%s%s%s%s%s", ID_hashed, time_hashed, &Rstr_hashed[0], Rtstr_hashed_0, Rtstr_hashed_1);
		h3_str[159]='\0';

		hash_descriptor[idx].process(&md, h3_str, strlen(h3_str)); //hash the string h3

		hash_descriptor[idx].done(&md, &k); //copy the produced value to k, k = H3(IDc, Tc, R, R')
		printf("\n\n");
		printf("k hash input: ");
		for(int i=0; i<sizeof(h3_str); i++) printf("%u ", h3_str[i]);
		printf("\n\n");
		printf("Calculated k = H3(IDc, Tc, R, R') = ");
		for(int i=0; i<sizeof(k); i++) printf("%u ", k[i]);

		//---------------------------------------------------MACk(IDc, Tc, R)

		printf("\n\nCalculating MACk(IDc, Tc, R)\n");
		if ((hmac_err = hmac_init(&hmac, idx, k, sizeof(k))) != CRYPT_OK) { //use the already registeres sha3 as the hashing algorithm
			printf("Error setting up hmac: %s\n", error_to_string(hmac_err));
		return;
		}

		printf("client ID length %d\n", strlen(init_msg.ID));
		if((hmac_err = hmac_process(&hmac, init_msg.ID, sizeof(init_msg.ID))) != CRYPT_OK) {
			printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return;
		}
		dstlen = sizeof(ID_mac);
		printf("sizeof(ID_mac) = %d\n", dstlen);
		if((hmac_err = hmac_done(&hmac, ID_mac, &dstlen)) != CRYPT_OK) {
			printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
		return;
		}

		ID_mac[31] = '\0';
		printf("ID mac: ");
		for(int i=0; i<strlen(ID_mac); i++) printf("%u ", ID_mac[i]);
		printf("\n");

		if((hmac_err = hmac_process(&hmac, buf, strlen(buf))) != CRYPT_OK) {
			printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return;
		}
		dstlen = sizeof(time_mac);
		if((hmac_err = hmac_done(&hmac, time_mac, &dstlen)) != CRYPT_OK) {
			printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
		return;
		}
		time_mac[31] = '\0';
		printf("time mac: ");
		for(int i=0; i<strlen(time_mac); i++) printf("%u ", time_mac[i]);
		printf("\n");

		printf("3 - Rcomb = %s\n", Rcomb);
		if((hmac_err = hmac_process(&hmac, Rcomb, sizeof(Rcomb))) != CRYPT_OK) {
			printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return;
		}
		dstlen = sizeof(Rstr_mac1);
		if((hmac_err = hmac_done(&hmac, Rstr_mac1, &dstlen)) != CRYPT_OK) {
			printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
		return;
		}
		Rstr_mac1[31] = '\0';
		printf("Rstr mac: ");
		for(int i=0; i<strlen(Rstr_mac1); i++) printf("%u ", Rstr_mac1[i]);
		printf("\n");
		
		int ret_bytes = snprintf(hmac_str, 96, "%s%s%s", ID_mac, time_mac, Rstr_mac1);
		printf("snprintf wrote %d bytes\n", ret_bytes);
		hmac_str[95] = '\0';
		printf("hmac_str ready: ");

		for(int i=0; i<sizeof(hmac_str); i++) printf("%u ", hmac_str[i]);
		printf("\n");

		
		if((hmac_err = hmac_process(&hmac, hmac_str, strlen(hmac_str))) != CRYPT_OK) {
			printf("Error processing hmac: %s\n", error_to_string(hmac_err));
			return;
		}

		dstlen = sizeof(hmac_str);
		if ((hmac_err = hmac_done(&hmac, hmac_res, &dstlen)) != CRYPT_OK) {
			printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
			return;
		}
		
		hmac_res[31] = '\0';

		//printf("\ncl_hmac:");

		//for(int i=0; i<sizeof(cl_hmac); i++){
			//printf("%u ", cl_hmac[1]);
		//}
		printf("hmac_res:");
		// check validity of received hmac
		for(int i=0; i<strlen(hmac_res); i++){
			printf("%u ", hmac_res[i]);
		}
		
		int sim = 0;
		printf("cl_hmac:");
    	for(int i=0; i<strlen(cl_hmac); i++){
    		printf(" %u", cl_hmac[i]);
    		if(cl_hmac[i] == hmac_res[i]) sim++;
 		}
 		printf("\n");
 		if(sim == 31) printf("MAC validation successful\n");
 		else printf("MAC validation failed\n");


		mpz_set_str(R[0], R_str[0], 10);
		mpz_set_str(R[1], R_str[1], 10);
		gmp_printf("R[0] = %Zd, R[1] = %Zd\n", R[0], R[1]);	
		do{
			fortuna_read(&rs, sizeof(rs), &prng); //select random rs
			printf("Random rs = %u\n", rs);
			mpz_set_ui(temp1, 0);
			mpz_set_ui(temp1, rs);
			gmp_printf("temp1 = %Zd\n", temp1);
			myzmulmod(&L[0], &temp1, &base_point[0], &m); //L = rs*P
			myzmulmod(&L[1], &temp1, &base_point[1], &m);
			gmp_printf("Calculated L = rs*P. \nL[0] = %Zd\nL[1] = %Zd\n", L[0], L[1]);
			myzmulmod(&Ls[0], &temp1, &R[0], &m); // Ls = rs * R
			myzmulmod(&Ls[1], &temp1, &R[1], &m);
			gmp_printf("Calculated Ls = rs*R. \nLs[0] = %Zd\nLs[1] = %Zd\n", Ls[0], Ls[1]);

			//--------------------------------------------AIDci = AIDci xor H2(IDc|| Ls)
			// this might need to be allocated with realloc
			dstlen = mpz_sizeinbase(Ls[0], 10);
			Ls_str_0 = (unsigned char *)malloc(dstlen*sizeof(unsigned char));
			dstlen = mpz_sizeinbase(Ls[1], 10);
			Ls_str_1 = (unsigned char *)malloc(dstlen*sizeof(unsigned char));

			mpz_get_str(Ls_str_0, 10, Ls[0]);
			mpz_get_str(Ls_str_1, 10, Ls[1]);

			printf("Ls_str_0 = ");
			for(int i=0; i<strlen(Ls_str_0); i++) printf("%u ", Ls_str_0[i]);
			printf("\n");
			
			printf("Ls_str_1 = ");
			for(int i=0; i<strlen(Ls_str_1); i++) printf("%u ", Ls_str_1[i]);
			printf("\n");

			dstlen = sizeof(init_msg.ID)+sizeof(Ls_str_0);
			t1 = malloc(sizeof(unsigned char)*dstlen);

			ret_bytes = snprintf(t1, dstlen, "%s%s", init_msg.ID, Ls_str_0); // IDci || Lci
			printf("t1 = %s\n", t1);

			idx = find_hash("sha256");
			if (idx == -1) {
			printf("Invalid hash name!\n");
			return;
			}

		// H2(IDci || Ls)
			hash_descriptor[idx].init(&md);//initialize the SHA 256 hash function

			hash_descriptor[idx].process(&md, t1, strlen(t1)); // produce the hashed IDci

			hash_descriptor[idx].done(&md, &t2); //copy the produced value to t2
			printf("t2 = %s\n", t2);

			//calculate next AID
			for (int i=0; i<strlen(client.AID); i++)
		  	{
		    	unsigned char temp = client.AID[i] ^ t2[i];
		    	client.next_AID[i] = temp;
		    	//printf("client.next_AID[%d] = %u\n", i, client.next_AID[i]);
		  	}
		  	client.AID[31] = '\0';

		    clientfd_s = fopen("client_db.csv", "a+");
		  	if(clientfd_s== NULL) printf("Error opening file\n");
		    printf("----- Check for collisions -----\n");
		    //char line[1024];
		    collision = 0;
		   	while(fgets(line, 150, clientfd_s)!=NULL){ //Read until EOF. TODO: check buffer size
		   		//printf("Read line\n");
		   		int i=0;
		   		char* tmp = strtok(line,"-");
		   		while(i<32){
		   			int num = atoi(tmp);
		   			//printf("num = %d\n", num);
		   			if(num == client.next_AID[i]) printf("Correct!! \n");
		   			else break;
		   			tmp = strtok(NULL,"-");
		   			i++;
				}
				if(i==32){
					collision = 1;
					printf("Collision with already registered client. Recalculating next AID.\n");
					fclose(clientfd_s);
					break;
				} 
			}
			if(collision==0) printf("Next AID is valid for use = ");
		}while (collision == 1);

		for(int i = 0; i<strlen(client.AID); i++) printf("%u ", client.next_AID[i]);
		printf("\n");
//MAC(IDc, Ts, L)

size = mpz_sizeinbase(L[0], 10) + 2;
printf("size = %d\n", size);
L_str_0 = (unsigned char*)malloc(size*sizeof(unsigned char));
size = mpz_sizeinbase(L[1], 10) + 2;
printf("size = %d\n", size);
L_str_1 = (unsigned char*)malloc(size*sizeof(unsigned char));

mpz_get_str(L_str_0, 10, L[0]);
mpz_get_str(L_str_1, 10, L[1]);
	
	//the HMAC of IDc is already stored in ID_mac
	
	
   	M2_time = time(NULL);
	//snprintf(time_str, 10, "%ld", M2_time);

	const int n2 = snprintf(NULL, 0, "%lu", M2_time);
	assert(n2 > 0);
	char time_str_2[n2+1];
	c = snprintf(time_str_2, n2+1, "%lu", M2_time);
	assert(time_str_2[n2] == '\0');
	assert(c == n2);
	printf("M2 sent at: %s seconds\n", time_str_2);


	printf("Timestamp = ");
	for(int i=0; i<strlen(time_str_2); i++){
		printf("%u ", time_str_2[i]);
	}
	printf("\n\n");

	if((hmac_err = hmac_process(&hmac, time_str_2, strlen(time_str_2))) != CRYPT_OK) {
		printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return -1;
	}
	dstlen = sizeof(time_str_2);
	if ((hmac_err = hmac_done(&hmac, time_mac, &dstlen)) != CRYPT_OK) {
		printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
	return -1;
	}
	time_mac[31] = '\0';
	printf("Time hmac = ");
	for(int i=0; i<sizeof(time_mac); i++){
		printf("%u ", time_mac[i]);
	}
	printf("\n\n");
	
	printf("L_str[0] = ");
	for(int i=0; i<strlen(L_str_0); i++) printf("%u ", L_str_0[i]);
	printf("\n");
	if((hmac_err = hmac_process(&hmac, L_str_0, strlen(L_str_0))) != CRYPT_OK) {
		printf("Error processing hmac: %s\n", error_to_string(hmac_err));
	return -1;
	}
	dstlen = sizeof(Lstr_mac_0);
	if ((hmac_err = hmac_done(&hmac, Lstr_mac_0, &dstlen)) != CRYPT_OK) {
		printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
	return -1;
	}
	Lstr_mac_0[31] = '\0';
	printf("Lstr_mac_0 hmac = ");
	for(int i=0; i<sizeof(Lstr_mac_0); i++){
		printf("%u ", Lstr_mac_0[i]);
	}
	printf("\n\n");

	printf("L_str[1] = ");
	for(int i=0; i<strlen(L_str_1); i++) printf("%u ", L_str_1[i]);
	printf("\n\n");
	if((hmac_err = hmac_process(&hmac, L_str_1, strlen(L_str_1))) != CRYPT_OK) {
		printf("Error processing hmac: %s\n", error_to_string(hmac_err));
	return -1;
	}
	dstlen = sizeof(Lstr_mac_1);
	if ((hmac_err = hmac_done(&hmac, Lstr_mac_1, &dstlen)) != CRYPT_OK) {
		printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
	return -1;
	}
	Lstr_mac_1[31] = '\0';
	printf("Lstr_mac_1 hmac = ");
	for(int i=0; i<sizeof(Lstr_mac_1); i++){
		printf("%u ", Lstr_mac_1[i]);
	}
	printf("\n\n");
	
	check_str = (unsigned char*)malloc(128* sizeof(unsigned char));

	snprintf(check_str, 128,"%s%s%s%s", ID_mac, time_mac, Lstr_mac_0, Lstr_mac_1);
	check_str[127] = '\0';
	printf("check_str = ");
	for(int i=0; i<strlen(check_str); i++){
		printf("%u ", check_str[i]);
	}
	printf("\n\n");
	if((hmac_err = hmac_process(&hmac, check_str, strlen(check_str))) != CRYPT_OK) {
		printf("Error processing hmac: %s\n", error_to_string(hmac_err));
	return -1;
	}
	//k = malloc(strlen(check_str)*sizeof(char));
	dstlen = sizeof(result);
	if ((hmac_err = hmac_done(&hmac, result, &dstlen)) != CRYPT_OK) {
		printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
	return -1;
	}//copy the produced value to result, result = HMAC(IDc, Ts, L)

	result[31] = '\0';
	printf("MACk(IDc,Ts,L) = ");
	for(int i = 0; i<sizeof(result); i++) printf("%u ", result[i]);
	printf("\n");

	//--------------------------send M2 = (AIDc, Ts, L, MACk(IDc, Ts, L))------------------------------
	bytes = send(newsockfd, cl_AID, 32, 0);		//TODO: check if this is in accordance with the way the client receives the data
	if(bytes<= 0){
        printf("Error sending the anonymous ID, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent AID - size = %ld bytes\n", bytes);

    for(int i=0; i<bytes; i++) printf("%u ", cl_AID[i]);
    printf("\n\n");

    bytes = send(newsockfd, &M2_time, sizeof(unsigned long), 0);
	if(bytes<= 0){
        printf("Error sending the current timestamp, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent timestamp - size = %ld bytes\n", bytes);

    size = mpz_sizeinbase(L[0], 10) + 2;

    bytes = send(newsockfd, &size, sizeof(size_t), 0);
	if(bytes<= 0){
        printf("Error sending L_str_0 size, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent L_str_0 size = %d, %ld bytes\n", size, bytes);
    for(int i = 0; i<bytes; i++) printf("%u ", L_str_0[i]);
    printf("\n\n");

    bytes = send(newsockfd, L_str_0, size, 0);
	if(bytes<= 0){
        printf("Error sending L_str_0, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent L_str_0 %s - size = %ld bytes\n", L_str_0, bytes);
    //for(int i = 0; i<bytes; i++) printf("%u ", L_str_0[i]);
    printf("\n\n");

	//for(int i = 0; i<bytes; i++) printf("%u ", L_str_0[i]);
    printf("\n\n");

    size = mpz_sizeinbase(L[1], 10) + 2;
    bytes = send(newsockfd, &size, sizeof(size_t), 0);
	if(bytes<= 0){
        printf("Error sending L_str_1 size, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent L_str_1 size = %d, %ld bytes\n", size, bytes);
 
    bytes = send(newsockfd, L_str_1, size, 0);
	if(bytes<= 0){
        printf("Error sending L_str_1, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent L_str_1 %s - size = %ld bytes\n", L_str_1, bytes);

    for(int i=0; i<bytes; i++) printf("%u ", L_str_1[i]);
    printf("\n\n");

    bytes = send(newsockfd, result, 32*sizeof(unsigned char), 0); //result = HMAC(IDc, Ts, L)
	if(bytes<= 0){
        printf("Error sending the HMAC result, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent HMAC result - size = %ld bytes\n", bytes);

    for(int i=0; i<bytes; i++) printf("%u ", result[i]);
    printf("\n\n");

    // --------------------------------------------------------generate the shared key----------------------------------------------------------------------
	if (register_hash(&blake2b_256_desc) == -1) { 
		printf("Error registering Blake2b.\n");
	return -1;
	}

	idx = find_hash("blake2b-256");	
	if (idx == -1) {
		printf("Invalid hash name!\n");
		return -1;
	}

	hash_descriptor[idx].init(&md);//initialize the Blake2b 256 hash function
	//attempt to use a diy hash list
	hash_descriptor[idx].process(&md, init_msg.ID, sizeof(init_msg.ID)); // produce the hashed IDci
	hash_descriptor[idx].done(&md, ID_hashed); 
	printf("ID_hashed = ");
	for(int i=0; i<sizeof(ID_hashed); i++) printf("%u ", ID_hashed[i]);
	ID_hashed[31] = '\0';
	printf("\n");
	// hash Tc
	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, buf, sizeof(buf)); 
	hash_descriptor[idx].done(&md, time_hashed);
	printf("time_hashed = ");
	for(int i=0; i<sizeof(time_hashed); i++) printf("%u ", time_hashed[i]);
	time_hashed[31] = '\0';
	printf("\n");

	//hash Ts
	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, time_str_2, sizeof(time_str_2)); //Ts
	hash_descriptor[idx].done(&md, server_time_hashed); 
	printf("server_time_hashed = ");
	for(int i=0; i<sizeof(server_time_hashed); i++) printf("%u ", server_time_hashed[i]);
	server_time_hashed[31] = '\0';
	printf("\n");

	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, Rcomb, sizeof(Rcomb)); //R
	hash_descriptor[idx].done(&md, Rstr_hashed); 
	printf("Rstr_hashed = ");
	for(int i=0; i<sizeof(Rstr_hashed); i++) printf("%u ", Rstr_hashed[i]);
	Rstr_hashed[31] = '\0';
	printf("\n");

	printf("L_str_0 = ");
	for(int i=0; i<strlen(L_str_0); i++) 
		printf("%u ", L_str_0[i]);
	//L_str_0[31] = '\0';
	printf("\n");

	if(hash_descriptor[idx].test() == CRYPT_OK) printf("Hash function test passed!!\n");
	else printf("Hash function test failed :( \n");
	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, L_str_0, strlen(L_str_0)); //L
	hash_descriptor[idx].done(&md, L_hashed_0); 
	printf("L_hashed_0 = ");
	for(int i=0; i<sizeof(L_hashed_0); i++) printf("%u ", L_hashed_0[i]);
	L_hashed_0[31] = '\0';
	printf("\n");

	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, L_str_1, sizeof(L_str_1));
	hash_descriptor[idx].done(&md, L_hashed_1);
	printf("L_hashed_1 = ");
	for(int i=0; i<sizeof(L_hashed_1); i++) printf("%u ", L_hashed_1[i]);
	L_hashed_1[31] = '\0';
	printf("\n");

	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, Ls_str_0, sizeof(Ls_str_0)); //Ls
	hash_descriptor[idx].done(&md, Ls_hashed_0); 
	printf("Ls_hashed_0 = ");
	for(int i=0; i<sizeof(Ls_hashed_0); i++) printf("%u ", Ls_hashed_0[i]);
	Ls_hashed_0[31] = '\0';
	printf("\n");	

	hash_descriptor[idx].init(&md);	
	hash_descriptor[idx].process(&md, Ls_str_1, strlen(Ls_str_1));
	hash_descriptor[idx].done(&md, Ls_hashed_1); 
	printf("Ls_hashed_1 = ");
	for(int i=0; i<sizeof(Ls_hashed_1); i++) printf("%u ", Ls_hashed_1[i]);
	Ls_hashed_1[31] = '\0';
	printf("\n");
		
	hash_descriptor[idx].init(&md);
	temp_size = 7*32;
	h4_str = malloc(temp_size * sizeof(char));
	snprintf(h4_str, temp_size, "%s%s%s%s%s%s%s", ID_hashed, time_hashed, server_time_hashed, Rstr_hashed, L_hashed_0, L_hashed_1, Ls_hashed_0);
	hash_descriptor[idx].process(&md, h4_str, strlen(h4_str)); //hash the string h3

	hash_descriptor[idx].done(&md, shared_key); //copy the produced value to shared_key, sk = H4(IDc, Tc, Ts, R, L, Lci)
	shared_key[31] = '\0';
	printf("shared key = ");
	for(int i=0; i<strlen(shared_key); i++) printf("%u ", shared_key[i]);
	
	printf("\n");

	mpz_clear(p);
    mpz_clear(m);
    mpz_clear(n);
    mpz_clear(h);
    mpz_clear(x);
    mpz_clear(seed);
    mpz_clear(curv[0]); mpz_init(curv[1]);
    mpz_clear(base_point[0]); mpz_init(base_point[1]);
    mpz_clear(randp[0]); mpz_init(randp[1]);
    mpz_clear(randPs[0]); mpz_init(randPs[1]);
    mpz_clear(tc); mpz_init(temp1); mpz_init(temp2);
    mpz_clear(hc);
    mpz_clear(Dc[0]); mpz_init(Dc[1]);
    mpz_clear(Rtonos[0]); mpz_init(Rtonos[1]); 
    mpz_clear(temp3[0]); mpz_init(temp3[1]);
    mpz_clear(R[0]); mpz_init(R[1]);
    mpz_clear(L[0]); mpz_init(L[1]);
    mpz_clear(Ls[0]); mpz_init(Ls[1]);
    mpz_clear(temp4); mpf_init(temp6);
    mpz_clear(temp7); mpf_init(temp8);
    mpf_clear(tc_float);

}

void lama_client(data_received *ID_client){

	mpz_t m, p, temp1, mrc, test[2], test1[2];
    mpz_t curv[2], base_point[2];
    mpz_t randPs[2];
    mpz_t dc[2], R[2], Lc[2], L[2], Rt[2];
    mpz_t rc, seed, rc_m, rc_f;
	prng_state prng;
	unsigned int temp_int;
	int sockfd, dc_size1, dc_size2, idx, hmac_idx, hmac_err, size, bytes, ssl_err, err;
	int rbytes;
	unsigned char ID_mac[32], time_mac[32], Rstr_mac1[32], Lstr_mac_0[32], Lstr_mac_1[32];
	unsigned char h3_str[160], k[32], hmac_str[96], hmac_res[32], *server_AID, result[32], *check_str, *Lstr_mac[2], *h4_str;
	unsigned char Rstr_hashed_0[32], Rstr_hashed_1[32], Rtstr_hashed_0[32], Rtstr_hashed_1[32], server_hmac[32], shared_key[32];
	unsigned char *R_str[2], *Rt_str[2], *L_str_0, *L_str_1, *Lc_str[2], *t1, t2[32], *time_str;
	unsigned char next_AID[33], buffer_u[8], tc[32], buffer[4],*Rcomb;
	unsigned char Lc_hashed1[32], Lc_hashed2[32], server_time_hashed[32], server_mac[32], ID_hashed[32], time_hashed[32], L_hashed_0[32], L_hashed_1[32];
	
	unsigned long timestamp, server_time;
	unsigned char rc_c;
	long sd;
	
	FILE *basep_fd;
	hmac_state hmac;
	hash_state md;
	struct pollfd fds;
	int timeout, dstlen;
	int nfds = 1;
	struct sockaddr_in saiServerAddress;
	size_t s1, s2;

	struct initialization_msg{
		char ID[4];
		unsigned long tc;
	}init_msg;

	mpz_init(p);
	mpz_init(temp1);
    mpz_init(m);
    mpz_init(mrc);
    mpz_init(curv[0]); mpz_init(curv[1]);
    mpz_init(base_point[0]); mpz_init(base_point[1]);
    mpz_init(randPs[0]); mpz_init(randPs[1]);
    mpz_init(R[0]); mpz_init(R[1]);
    mpz_init(Lc[0]); mpz_init(Lc[1]);
    mpz_init(L[0]); mpz_init(L[1]);
    mpz_init(Rt[0]); mpz_init(Rt[1]);
    mpz_init(dc[0]); mpz_init(dc[1]);
    mpz_init(rc);mpz_init(rc_m);mpz_init(rc_f);
    mpz_init(seed);
    mpz_init(test[0]); mpz_init(test[1]);
    mpz_init(test1[0]); mpz_init(test1[1]);

//----------------------------Authentication Phase-----------------------------------------------------------//
    //gmp_randinit(stat, GMP_RAND_ALG_LC, 120);

    int fd = fopen("/dev/urandom", "r");//initialize the seed for the random generator using /dev/urandom
    read(fd, buffer_u, 8);

	if ((err = fortuna_start(&prng)) != CRYPT_OK) {
		printf("Start error: %s\n", error_to_string(err));
	}
	/* add entropy */
	if ((err = fortuna_add_entropy(buffer_u, 8, &prng))!= CRYPT_OK) {
		printf("Add_entropy error: %s\n", error_to_string(err));
	}
	/* ready state*/
	if ((err = fortuna_ready(&prng)) != CRYPT_OK) {
		printf("Ready error: %s\n", error_to_string(err));
	}

	//fortuna_read(buffer, sizeof(buffer), &prng);
    printf("Beginning authentication...\n");
	//fortuna_read(rc, sizeof(rc), &prng); //generate random number rc

	basep_fd=fopen("pfile.txt", "r"); //open the parameters file to read the order of the field m
    gmp_fscanf(basep_fd, "%Zd %Zd %Zd %Zd %Zd %Zd %Zd %Zd", curv[0], curv[1], p, base_point[0], base_point[1], randPs[0], randPs[1], m);
    fclose(basep_fd);

    printf("Read %lu bytes from fortuna\n",fortuna_read(buffer, sizeof(buffer), &prng));	
	for(int i=0; i<strlen(buffer); i++){
		printf("%u \n", buffer[i]);	
	}
	
	sd = (long)buffer[0]|(long)buffer[1]|(long)buffer[2]|(long)buffer[3]; //convert the charecters generated by fortuna to long integers 
	mpz_set_ui(seed, sd);

	fortuna_read(&rc_c, 1, &prng); //select random rs
	printf("Random rc_c = %u\n", rc_c);
	mpz_set_ui(rc_m, 0);
	mpz_set_ui(rc_m, &rc_c);
    mpz_cdiv_r(rc_f, rc_m, m); //create random number in Zn* | TODO: is m the order of the curve?? 
    unsigned int rc_ui = mpz_get_ui(rc_f);
    printf("rc_ui = %u\n", rc_ui); 
    gmp_printf("rc E Zn = %Zd\n", rc_f);
    //mpz_set_ui(rc_f, 0);
    //mpz_set_ui(rc_f, rc_ui);
    //gmp_printf("rc E Zn = %Zd\n", rc_f);
    mpz_set(rc, rc_f);
    //temp_int = (unsigned int)rc[0]|(unsigned int)rc[1]|(unsigned int)rc[2]|(unsigned int)rc[3]|(unsigned int)rc[4]|(unsigned int)rc[5]|(unsigned int)rc[6]|(unsigned int)rc[7];
    //mpz_set_ui(temp1, rc);
    mpz_set_str(dc[0], ID_client->Dc_str_1, 10);
    mpz_set_str(dc[1], ID_client->Dc_str_2, 10);
    gmp_printf("dc: %Zd, %Zd\n", dc[0], dc[1]);
    //mpz_tdiv_q(mrc, temp1, m); //divide the random rc number modulo m
    gmp_printf("rci mod m %Zd\n", rc);
    myzmulmod(&R[0], &rc, &base_point[0], &m); //R = rci*P
    myzmulmod(&R[1], &rc, &base_point[1], &m);
    gmp_printf("R: %Zd, %Zd\n", R[0], R[1]);
    //gmp_printf("mrc = %Zd\n", mrc);
    gmp_printf("base_point[0] = %Zd\n", base_point[0]);
    gmp_printf("base_point[1] = %Zd\n", base_point[1]);
    gmp_printf("m = %Zd\n", m);
    printf("R = rci*P\n");
    gmp_printf("R[0] = %Zd\n", R[0]);
    gmp_printf("R[1] = %Zd\n", R[1]);

    gmp_printf("dc[0] = %Zd - dc[1] = %Zd - m = %Zd\n", dc[0], dc[1], m);

    myzaddmod(&Rt[0], &dc[0], &R[0], &m); // R' = Dci + R
    myzaddmod(&Rt[1], &dc[1], &R[1], &m);
    printf("R' = Dci + R\n");
    gmp_printf("Rt[0] = %Zd\n", Rt[0]);
    gmp_printf("Rt[1] = %Zd\n", Rt[1]);

    timestamp = time(NULL); //get current timestamp

    if (register_hash(&sha3_256_desc) == -1) { //register the third hash function SHA3
		printf("Error registering SHA3.\n");
	return -1;
	}

	idx = find_hash("sha3-256");	
	if (idx == -1) {
		printf("Invalid hash name!\n");
		return -1;
	}
	printf("Hashing R using sha3-256\n");
	size = mpz_sizeinbase(R[0], 10);
	R_str[0] = malloc(size*sizeof(char));
	size = mpz_sizeinbase(R[1], 10);
	R_str[1] = malloc(size*sizeof(char));

	size = mpz_sizeinbase(Rt[0], 10);
	Rt_str[0] = malloc(size*sizeof(char));
	size = mpz_sizeinbase(Rt[1], 10);
	Rt_str[1] = malloc(size*sizeof(char));

	mpz_get_str(R_str[0], 10, R[0]);
	mpz_get_str(R_str[1], 10, R[1]);
	printf("R_str[0] = %s\n", R_str[0]);
	printf("R_str[1] = %s\n", R_str[1]);
	mpz_get_str(Rt_str[0], 10, Rt[0]);
	mpz_get_str(Rt_str[1], 10, Rt[1]);

	hash_descriptor[idx].init(&md);//initialize the SHA3 256 hash function
	//attempt to use a diy hash list
	printf("1 - ID_client.ID =");
	for(int i=0; i<4; i++) printf("%u ", ID_client->ID[i]);
	printf("\n");
	hash_descriptor[idx].process(&md, ID_client->ID, 4); // produce the hashed IDci
	hash_descriptor[idx].done(&md, ID_hashed); 
	ID_hashed[31] = '\0';

	printf("ID_hashed = ");
	for(int i=0; i<sizeof(ID_hashed); i++) printf("%u ", ID_hashed[i]);

	//printf("sizeof ID hased: %d, strlen ID hased: %d\n", sizeof(ID_hashed), strlen(ID_hashed));
	//printf("\n");

	
	const int n1 = snprintf(NULL, 0, "%lu", timestamp);
	//printf("n1 = %d\n", n1);
	assert(n1 > 0);
	char buf[n1+1];
	int c = snprintf(buf, n1+1, "%lu", timestamp);
	//printf("sizeof(buf) = %d, strlen(buf)=%d\n", sizeof(buf), strlen(buf));
	assert(buf[n1] == '\0');
	assert(c == n1);


	printf("2 - time_str = %s\n", buf);
	hash_descriptor[idx].process(&md, buf, sizeof(buf));
	hash_descriptor[idx].done(&md, time_hashed); 
	printf("time_hashed = ");
	for(int i=0; i<sizeof(time_hashed); i++) printf("%u ", time_hashed[i]);
	time_hashed[31]='\0'; //without this strlne(time_hashed) returns the values 64!!!

	printf("sizeof time hased: %d, strlen time hased: %d\n", sizeof(time_hashed), strlen(time_hashed));
	printf("\n");

	Rcomb = (char *)malloc(strlen(R_str[0])+strlen(R_str[1]));
	strcpy(Rcomb, R_str[0]);
	strcat(Rcomb, R_str[1]);
	s2 = strlen(Rcomb);
	Rcomb[s2-1] = '\0';

	printf("3 - Rcomb = %s\n", Rcomb);

	hash_descriptor[idx].process(&md, Rcomb, sizeof(Rcomb));
	hash_descriptor[idx].done(&md, Rstr_hashed_0); 

	Rstr_hashed_0[31] = '\0';

	printf("Rstr_hashed = ");
	for(int i=0; i<sizeof(Rstr_hashed_0); i++) printf("%u ", Rstr_hashed_0[i]);
	printf("\n");
	
	printf("4 - Rt_str[0] = %s\n", Rt_str[0]);
	hash_descriptor[idx].process(&md, Rt_str[0], sizeof(Rt_str[0]));
	hash_descriptor[idx].done(&md, Rtstr_hashed_0); 
	printf("Rtstr_hashed_0 = ");
	for(int i=0; i<sizeof(Rtstr_hashed_0); i++) printf("%u ", Rtstr_hashed_0[i]);
	Rtstr_hashed_0[31] = '\0';
	printf("\n");

	printf("5 - Rt_str[1] = %s\n", Rt_str[1]);
	hash_descriptor[idx].process(&md, Rt_str[1], sizeof(Rt_str[1]));
	hash_descriptor[idx].done(&md, Rtstr_hashed_1); 

	printf("Rtstr_hashed_1 = ");
	for(int i=0; i<sizeof(Rtstr_hashed_1); i++) printf("%u ", Rtstr_hashed_1[i]);
	Rtstr_hashed_1[31] = '\0';
	printf("\n");
	
	int rb = snprintf(h3_str, sizeof(h3_str),"%s%s%s%s%s", ID_hashed, time_hashed, Rstr_hashed_0, Rtstr_hashed_0, Rtstr_hashed_1);
	printf("snprintf writes %d bytes\n", rb );
	//h3_str[159]='\0';
	hash_descriptor[idx].process(&md, h3_str, strlen(h3_str)); //hash the string h3
	hash_descriptor[idx].done(&md, k); //copy the produced value to k, k = H3(IDc, Tc, R, R')
	printf("k hash input: ");
	for(int i=0; i<sizeof(h3_str); i++) printf("%u ", h3_str[i]);
	printf("\n\n");
	printf("k = H3(IDc, Tc, R, R'): ");
	for(int i=0; i<sizeof(k); i++) printf("%u ", k[i]);
	printf("\n\n");
	//---------------------------------------send M1 = {AIDc, Tc, R, MACk(ID, Tc, R)}----------------------------------------------

	//---------------------------------------------calculate MACk(ID, Tc, R)-------------------------------------------------------
printf("R_str[0] = %s\n", R_str[0]);
	if ((hmac_err = hmac_init(&hmac, idx, k, strlen(k))) != CRYPT_OK) { //use the already registeres sha3 as the hashing algorithm
		printf("Error setting up hmac: %s\n", error_to_string(hmac_err));
		return -1;
	}

	printf("client ID length %d\n", sizeof(ID_client->ID));
	if((hmac_err = hmac_process(&hmac, ID_client->ID, sizeof(ID_client->ID))) != CRYPT_OK) {
		printf("Error processing hmac: %s\n", error_to_string(hmac_err));
	return;
	}
	dstlen = sizeof(ID_mac);
	if((hmac_err = hmac_done(&hmac, ID_mac, &dstlen)) != CRYPT_OK) {
		printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
	return;
	}
		printf("test\n");
	//	ID_mac[31] = '\0';
		printf("ID mac: ");
		for(int i=0; i<strlen(ID_mac); i++) printf("%u ", ID_mac[i]);
		printf("\n");

		if((hmac_err = hmac_process(&hmac, buf, strlen(buf))) != CRYPT_OK) {
			printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return;
		}
		printf("test\n");
		dstlen = sizeof(time_mac);
		char time_mac_test[31];
		if((hmac_err = hmac_done(&hmac, time_mac_test, &dstlen)) != CRYPT_OK) {
			printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
		return;
		}
		time_mac[31] ='\0';
		printf("time mac: ");
		for(int i=0; i<strlen(time_mac); i++) printf("%u ", time_mac[i]);
		printf("\n");

		printf("3 - Rcomb = %s\n", Rcomb);
		if((hmac_err = hmac_process(&hmac, Rcomb, sizeof(Rcomb))) != CRYPT_OK) {
			printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return;
		}
		dstlen = sizeof(Rstr_mac1);
		if((hmac_err = hmac_done(&hmac, Rstr_mac1, &dstlen)) != CRYPT_OK) {
			printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
		return;
		}
		Rstr_mac1[31] ='\0';
		printf("Rstr mac: ");
		for(int i=0; i<strlen(Rstr_mac1); i++) printf("%u ", Rstr_mac1[i]);
		printf("\n");

	int ret_bytes = snprintf(hmac_str, sizeof(hmac_str), "%s%s%s", ID_mac, time_mac, Rstr_mac1);
	hmac_str[95] = '\0';

	printf("Hash input: ");
	for(int i=0; i<strlen(hmac_str); i++) printf("%u ", hmac_str[i]);

	if((hmac_err = hmac_process(&hmac, hmac_str, strlen(hmac_str))) != CRYPT_OK) {
		printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return -1;
	}
	dstlen = sizeof(hmac_str);

	if ((hmac_err = hmac_done(&hmac, hmac_res, &dstlen)) != CRYPT_OK) {
		printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
		return -1;
	}
	hmac_res[31] = '\0';
//printf(" MACk(ID, Tc, R): %s\n", hmac_res);
	printf("\nHash output: ");
	for(int i=0; i<strlen(hmac_res); i++) printf("%u ", hmac_res[i]);
	printf("\n");
	printf("size of hash output = %d\n", sizeof(hmac_res));
	//send M1 to the server
	//initialize connection
	printf("Setting up the connection...\n");
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	//sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sockfd < 0){ 
        printf("Error opening socket\n");
        return -1;
    }
    
	bzero((char *) &saiServerAddress, sizeof(saiServerAddress));
	saiServerAddress.sin_family = AF_INET;
	saiServerAddress.sin_addr.s_addr = inet_addr("127.0.0.1");
	saiServerAddress.sin_port = htons(1506);
	memset(saiServerAddress.sin_zero, '\0', sizeof(saiServerAddress.sin_zero));

	printf("PORT - %d\n", saiServerAddress.sin_port);

	if(connect(sockfd, (struct sockaddr *)&saiServerAddress, sizeof(saiServerAddress)) <0 ){
		printf("Connection to the server failed %s\n", strerror(errno));
		return;
	}
	printf("R_str[0] = %s\n", R_str[0]);
	printf("Connected\n");
	s1 = strlen(R_str[0]);
	//R_str[0][s1-1] = '\0';
	//printf("size of R[0] = %d\n", s1 );
	printf("--------------------------------------------------------Sending M1 to server--------------------------------------------------------------------\n");
	bytes = send(sockfd, &s1 , sizeof(s1), 0);
	if(bytes<= 0){
        printf("Error sending first size parameter, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent size - size = %ld bytes\n", bytes);

    s2 = strlen(R_str[1]);
    //R_str[1][s2-1] = '\0';
    bytes = send(sockfd, &s2, sizeof(s2), 0);
	if(bytes<= 0){
        printf("Error sending second size parameter, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent size - size = %ld bytes\n", bytes);

    printf("ID_client.AID \n");
    for(int i=0;i<32; i++){
    	printf("%u ", ID_client->AID[i]);
    }
	bytes = send(sockfd, ID_client->AID, 33*sizeof(char), 0);
	if(bytes<= 0){
        printf("Error sending the anonymous ID, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent AID - size = %ld bytes\n", bytes);

    bytes = send(sockfd, &timestamp, sizeof(unsigned long), 0);
	if(bytes<= 0){
        printf("Error sending the current timestamp, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent timestamp - size = %ld bytes\n", bytes);

    bytes = send(sockfd, R_str[0], s1, 0);
	if(bytes<= 0){
        printf("Error sending R[0], %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent R[0] %s - size = %ld bytes\n", R_str[0], bytes);
  

    bytes = send(sockfd, R_str[1], s2, 0);
	if(bytes<= 0){
        printf("Error sending R[1], %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent R[1] %s - size = %ld bytes\n", R_str[1], bytes);
 
    bytes = send(sockfd, &hmac_res, sizeof(hmac_res), 0);
	if(bytes<= 0){
        printf("Error sending the HMAC result, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent HMAC result - size = %ld bytes\n", bytes);


	// ----------------------------------------------receive M2 = {AIDc, Ts, L, MACk(IDc, Ts, L)}-----------------------------
    // TODO: Allocate the required space for the variables

    server_AID = (unsigned char *)malloc(32 * sizeof(unsigned char)); //we use the assumption that the AID of the client is always 3 bytes long
    size = mpz_sizeinbase(R[0], 10) + 2;
	L_str_0 = (unsigned char *)malloc(size*sizeof(unsigned char));
	size = mpz_sizeinbase(R[1], 10) + 2;
	L_str_1 = (unsigned char *)malloc(size*sizeof(unsigned char));

	printf("--------------------------------------Receiving M2 = {AIDc, Ts, L, MACk(IDc, Ts, L)}---------------------------------\n");

    bytes = recv(sockfd, server_AID, 32, 0);
	if(bytes<= 0){
        printf("Error receiving the anonymous ID, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received AID - size = %ld bytes\n", bytes);

    for(int i=0; i<bytes; i++) printf("%u ", server_AID[i]);
    printf("\n");

    bytes = recv(sockfd, &server_time, sizeof(unsigned long), 0);
	if(bytes<= 0){
        printf("Error receiving the current timestamp, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received Ts - size = %ld bytes\n", bytes);

	const int n2 = snprintf(NULL, 0, "%lu", server_time);
	assert(n2 > 0);
	char server_timestamp[n2+1];
	c = snprintf(server_timestamp, n2+1, "%lu", server_time);
	assert(server_timestamp[n2] == '\0');
	assert(c == n2);
	printf("M2 sent by server at: %s seconds\n", server_timestamp);


    //size = mpz_sizeinbase(R[0], 10) + 2;
    bytes = recv(sockfd, &size, sizeof(size_t), 0);
	if(bytes<= 0){
        printf("Error receiving L[0] size, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received L[0] size = %d, %ld bytes\n", size, bytes);

    bytes = recv(sockfd, L_str_0, size, 0);
	if(bytes<= 0){
        printf("Error receiving L[0], %s\n", strerror(errno));
        exit(-1);
    }else printf("Received L[0] - size = %ld bytes\n", bytes);

    for(int i=0; i<bytes; i++) printf("%u ", L_str_0[i]);
    printf("\n");

    //size = mpz_sizeinbase(R[1], 10) + 2;
    bytes = recv(sockfd, &size, sizeof(size_t), 0);
	if(bytes<= 0){
        printf("Error receiving L[1] size, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received L[1] size = %d, %ld bytes\n", size, bytes);

    bytes = recv(sockfd, L_str_1, size, 0);
	if(bytes<= 0){
        printf("Error receiving L[1], %s\n", strerror(errno));
        exit(-1);
    }else printf("Received L[1] - size = %ld bytes\n", bytes);

    for(int i=0; i<bytes; i++) printf("%u ", L_str_1[i]);
    printf("\n");

    bytes = recv(sockfd, server_hmac, 32, 0);
	if(bytes<= 0){
        printf("Error receiving the HMAC result, %s\n", strerror(errno));
        exit(-1);
    }else printf("Received HMAC result - size = %ld bytes\n", bytes);

    for(int i=0; i<bytes; i++) printf("%u ", server_hmac[i]);
    printf("\n");

    //calculate the MAC of IDc, Ts, L to check the validity of the MAC received by the server

    printf("----------------------------------------Checking the validity of MACk(IDc, Ts, L)--------------------------------\n");
	
	//the HMAC of IDc is already stored in ID_mac
	printf("Timestamp = ");
	for(int i=0; i<strlen(server_timestamp); i++) printf("%u ", server_timestamp[i]);
	printf("\n\n");
	if((hmac_err = hmac_process(&hmac, server_timestamp, 10)) != CRYPT_OK) {
		printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return;
	}
	dstlen = sizeof(server_timestamp);
	
	if ((hmac_err = hmac_done(&hmac, time_mac, &dstlen)) != CRYPT_OK) {
		printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
		return;
	}
	time_mac[31] = '\0';
	printf("Time mac = ");
	for(int i=0; i<strlen(time_mac); i++) printf("%u ", time_mac[i]);
	printf("\n\n");
	

	printf("L_str_0 = %s\n", L_str_0);

	if((hmac_err = hmac_process(&hmac, L_str_0, strlen(L_str_0))) != CRYPT_OK) {
		printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return;
	}

	dstlen = sizeof(Lstr_mac_0);
	if ((hmac_err = hmac_done(&hmac, Lstr_mac_0, &dstlen)) != CRYPT_OK) {
		printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
		return;
	}
	Lstr_mac_0[31] = '\0';
	printf("Lstr_mac_0 = ");
	for(int i=0; i<strlen(Lstr_mac_0); i++) printf("%u ", Lstr_mac_0[i]);
	printf("\n\n");


	printf("L_str_1 = %s\n", L_str_1);
	if((hmac_err = hmac_process(&hmac, L_str_1, strlen(L_str_1))) != CRYPT_OK) {
		printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return;
	}
	dstlen = sizeof(Lstr_mac_1);
	if ((hmac_err = hmac_done(&hmac, Lstr_mac_1, &dstlen)) != CRYPT_OK) {
		printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
		return;
	}
	Lstr_mac_1[31] = '\0';
	printf("Lstr_mac_1 = ");
	for(int i=0; i<strlen(Lstr_mac_1); i++) printf("%u ", Lstr_mac_1[i]);
	printf("\n\n"); 

	int temp_size = 128;
	check_str = (unsigned char* )malloc(temp_size * sizeof(unsigned char));

	snprintf(check_str, temp_size, "%s%s%s%s", ID_mac, time_mac, Lstr_mac_0, Lstr_mac_1); //one string containing all the values (hashed)
	check_str[127] = '\0'; 
	printf("check_str = ");
	for(int i=0; i<strlen(check_str); i++) printf("%u ", check_str[i]);
	printf("\n\n"); 
	if((hmac_err = hmac_process(&hmac, check_str, strlen(check_str))) != CRYPT_OK) {
		printf("Error processing hmac: %s\n", error_to_string(hmac_err));
		return;
	}
	dstlen = sizeof(result);

	if((hmac_err = hmac_done(&hmac, result, &dstlen)) != CRYPT_OK) {
		printf("Error finishing hmac: %s\n", error_to_string(hmac_err));
		return;
	} // result = HMAC(IDc, Ts, L)

	result[31] = '\0';
	printf("result = ");
	for(int i=0; i<sizeof(result); i++) printf("%u ", result[i]);
	printf("\n"); 

	int integrity_test = 0;
	for(int i = 0; i < 32; i++){
		if(result[i]!=server_hmac[i]) integrity_test++;
	}
	if(integrity_test!=0){
		printf("MAC integrity check failed\n");
		return;
	}else{
		printf("MAC integrity check successful\n");
		mpz_set_str(test[0], L_str_0, 10);
		mpz_set_str(test[1], L_str_1, 10);
		printf("test\n");

		gmp_printf("rc = %Zd, L[0] = %Zd, L[1] = %Zd\n", rc, test[0], test[1]);
		myzmulmod(&test1[0], &rc, &test[0], &m); // Lci = rci * L
		myzmulmod(&test1[1], &rc, &test[1], &m);

		gmp_printf("Calculated Lc, Lc[0] = %Zd, Lc[1] = %Zd\n", test1[0], test1[1]); 

		temp_size = mpz_sizeinbase(test1[0], 10) + 2;
		Lc_str[0] = (unsigned char*)malloc(temp_size);
		temp_size = mpz_sizeinbase(test1[1], 10) + 2;
		Lc_str[1] = (unsigned char*)malloc(temp_size);
		
		mpz_get_str(Lc_str[0], 10, test1[0]);
		mpz_get_str(Lc_str[1], 10, test1[1]);
		printf("Lc_str[0] = %s\n", Lc_str[0]);
		printf("Lc_str[1] = %s\n", Lc_str[1]);
	}
		//calculate the shared key

	if (register_hash(&blake2b_256_desc) == -1) { 
		printf("Error registering Blake2b.\n");
	return -1;
	}

	idx = find_hash("blake2b-256");	
	if (idx == -1) {
		printf("Invalid hash name!\n");
		return -1;
	}

	hash_descriptor[idx].init(&md);//initialize the Blake2b 256 hash function
	//attempt to use a diy hash list
	hash_descriptor[idx].process(&md, ID_client->ID, sizeof(ID_client->ID)); // produce the hashed IDci
	hash_descriptor[idx].done(&md, ID_hashed); 
	printf("ID_hashed = ");
	for(int i=0; i<sizeof(ID_hashed); i++) printf("%u ", ID_hashed[i]);
	ID_hashed[31] = '\0';
	printf("\n");

	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, buf, sizeof(buf)); //Tc
	hash_descriptor[idx].done(&md, time_hashed);
	printf("time_hashed = ");
	for(int i=0; i<sizeof(time_hashed); i++) printf("%u ", time_hashed[i]);
	time_hashed[31] = '\0';
	printf("\n");

	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, server_timestamp, sizeof(server_timestamp)); //Ts
	hash_descriptor[idx].done(&md, server_time_hashed); 
	printf("server_time_hashed = ");
	for(int i=0; i<sizeof(server_time_hashed); i++) printf("%u ", server_time_hashed[i]);
	server_time_hashed[31] = '\0';
	printf("\n");

	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, Rcomb, sizeof(Rcomb)); //R
	hash_descriptor[idx].done(&md, Rstr_hashed_0); 
	printf("Rstr_hashed_0 = ");
	for(int i=0; i<sizeof(Rstr_hashed_0); i++) printf("%u ", Rstr_hashed_0[i]);
	Rstr_hashed_0[31] = '\0';
	printf("\n");

	printf("L_str_0 = ");
	for(int i=0; i<strlen(L_str_0); i++) 
		printf("%u ", L_str_0[i]);
	//L_str_0[31] = '\0';
	printf("\n");

	if(hash_descriptor[idx].test() == CRYPT_OK) printf("Hash function test passed!!\n");
	else printf("Hash function test failed :( \n");
	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, L_str_0, strlen(L_str_0)); //L
	hash_descriptor[idx].done(&md, L_hashed_0); 
	printf("L_hashed_0 = ");
	for(int i=0; i<sizeof(L_hashed_0); i++) printf("%u ", L_hashed_0[i]);
	L_hashed_0[31] = '\0';
	printf("\n");

	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, L_str_1, sizeof(L_str_1));
	hash_descriptor[idx].done(&md, L_hashed_1);
	printf("L_hashed_1 = ");
	for(int i=0; i<sizeof(L_hashed_1); i++) printf("%u ", L_hashed_1[i]);
	L_hashed_1[31] = '\0';
	printf("\n");

	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, Lc_str[0], sizeof(Lc_str[0])); //Lc
	hash_descriptor[idx].done(&md, Lc_hashed1); 
	printf("Lc_hashed1 = ");
	for(int i=0; i<sizeof(Lc_hashed1); i++) printf("%u ", Lc_hashed1[i]);
	Lc_hashed1[31] = '\0';
	printf("\n");	

	hash_descriptor[idx].init(&md);	
	hash_descriptor[idx].process(&md, Lc_str[1], sizeof(Lc_str[1]));
	hash_descriptor[idx].done(&md, Lc_hashed2); 
	printf("Lc_hashed2 = ");
	for(int i=0; i<sizeof(Lc_hashed2); i++) printf("%u ", Lc_hashed2[i]);
	Lc_hashed2[31] = '\0';
	printf("\n");
		
	hash_descriptor[idx].init(&md);
	temp_size = 7*32;
	h4_str = (unsigned char*)malloc(temp_size);
	snprintf(h4_str, temp_size, "%s%s%s%s%s%s%s", ID_hashed, time_hashed, server_time_hashed, Rstr_hashed_0, L_hashed_0, L_hashed_1, Lc_hashed1);
	hash_descriptor[idx].process(&md, h4_str, strlen(h4_str)); //hash the string h3


	hash_descriptor[idx].done(&md, shared_key); //copy the produced value to shared_key, sk = H4(IDc, Tc, Ts, R, L, Lci)
	shared_key[31] = '\0';
	printf("shared key = ");
	for(int i=0; i<strlen(shared_key); i++) printf("%u ", shared_key[i]);

	printf("\n");
	//---------------------------------------------------------------------------------------------------------------------
		
	if (register_hash(&sha256_desc) == -1) {
		printf("Error registering SHA256.\n");
	return -1;
	}

	dstlen = sizeof(ID_client->ID)+strlen(Lc_str[0]);
	t1 = malloc(sizeof(unsigned char)*dstlen);
	printf("t1 allocated\n");
	ret_bytes = snprintf(t1, dstlen, "%s%s", ID_client->ID, &Lc_str[0]); // IDci || Lci
	printf("t1 = %s\n", t1);
	printf("retbytes set\n");
	idx = find_hash("sha256");
	if (idx == -1) {
		printf("Invalid hash name!\n");
		return;
	}

	// H2(IDci || Ls)
	hash_descriptor[idx].init(&md);//initialize the SHA 256 hash function
	hash_descriptor[idx].process(&md, t1, strlen(t1)); // produce the hashed IDci
	printf("procesed\n");
	hash_descriptor[idx].done(&md, &t2); //copy the produced value to t2
	printf("done\n");
	printf("t2 = %s\n", t2);

	//calculate next AID
	for (int i=0; i<32; i++)
	{
		unsigned char temp = ID_client->AID[i] ^ t2[i];
		ID_client->next_AID[i] = temp;
		printf("%u ", ID_client->next_AID[i]);
	}



	mpz_clear(p);
	mpz_clear(temp1);
    mpz_clear(m);
    mpz_clear(mrc);
    mpz_clear(curv[0]); mpz_clear(curv[1]);
    mpz_clear(base_point[0]); mpz_clear(base_point[1]);
    mpz_clear(randPs[0]); mpz_clear(randPs[1]);
    mpz_clear(R[0]); mpz_clear(R[1]);
    mpz_clear(Lc[0]); mpz_clear(Lc[1]);
    mpz_clear(L[0]); mpz_clear(L[1]);
    mpz_clear(Rt[0]); mpz_clear(Rt[1]);
    mpz_clear(dc[0]); mpz_clear(dc[1]);
    mpz_clear(rc);mpz_clear(rc_m);mpz_clear(rc_f);
    mpz_clear(seed);
    mpz_clear(test[0]); mpz_clear(test[1]);
    mpz_clear(test1[0]); mpz_clear(test1[1]);

} 
