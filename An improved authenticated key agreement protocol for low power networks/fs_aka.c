/*---------------------------------------------FS-AKA------------------------------*/
int _modbus_fs_aka_client(modbus_t *ctx){

//Initialization Phase
    mpz_t p, m, n, seed, h;
    mpz_t curv[2], base_point[2];
    mpz_t randp[2];
    mpz_t random_a, random_A[2];
    mpz_t B_point[2];
    mpz_t at[2];
    mpz_t u[2]; mpz_t U[2];
    mpz_t pw;
    mpz_t pass_n;

    modbus_tcp_t *ctx_tcp = ctx->backend_data;
    long D, sd = 0;
    int socket1;
    int auth1=0, auth2=0;//variables to check the equality between Yb and hashcode
    unsigned int sizes[5] = {0};
    size_t rc, random_a_size, curv_size, m_size;
    int randp_size;
    size_t u_size, at_size;
    unsigned int temp_size1, temp_size2;
    struct sockaddr_in srv_addr;
    struct timeval tv;
    unsigned char **curv_str, **randp_str, **B_point_str, **A_str, **U_str, **at_str;
    char *m_str, *random_a_str, *u_str;
    char pass[] = "123456";
    char finalkey_v2[32];
    char auth_msg[2];
    unsigned char **hashcode, **Yb_str, *temp_str, finalkey[32];
    gmp_randinit(stat, GMP_RAND_ALG_LC, 120);
    int temp1 = 20;
    SHA256_CTX ctx1;

    sd=0; 
    mpz_init(p);
    mpz_init(m);
    mpz_init(n);
    mpz_init(h);
    mpz_init(seed);
    mpz_init(curv[0]); mpz_init(curv[1]);
    mpz_init(base_point[0]); mpz_init(base_point[1]);
    mpz_init(randp[0]); mpz_init(randp[1]);
    mpz_init(random_a); 
    mpz_init(random_A[0]);mpz_init(random_A[1]);
    mpz_init(B_point[0]); mpz_init(B_point[1]);
    mpz_init(at[0]); mpz_init(at[1]);
    mpz_init(pw);
    mpz_init(u[0]); mpz_init(u[1]);
    mpz_init(U[0]); mpz_init(U[1]);
    mpz_init(pass_n);


    srand((unsigned) getpid());
    sd=rand();
    mpz_set_ui(seed,sd);

    gmp_randseed(stat, seed);
    D=228;
    CMmethod(D, &p, &m, curv);//p:finite field orber, m curve order
    rand_point(curv, &p, randp); //genarate random point modulo p
    //TODO: FIND SIZE OF CURV, RANDP AND M AND ALLOCATE FOR STR

    //Allocate memory for curve_str
    curv_str = (unsigned char **)malloc(2* sizeof(unsigned char*));
    curv_size = mpz_sizeinbase(curv[0], 10) + 2; //store the size of curv[0] in chars
    curv_str[0] = (unsigned char *)malloc(curv_size*sizeof(unsigned char)); //allocate space equal to curv_size/8 + 1 bytes
    sizes[0] = htonl(curv_size);


    //-----------------------DEBUG------------------------------
    if(curv_size == (mpz_sizeinbase(curv[1], 10) + 2)) printf("sizeof(curv[0]) == sizeof(curv[1]!!!!!!!!!!!!!!!!\n");
    //----------------------------------------------------------
    curv_size = mpz_sizeinbase(curv[1], 10) + 2; //store the size of curv[1] in bits
    curv_str[1] = (unsigned char *)malloc(curv_size*sizeof(unsigned char)); //allocate space equal to curv_size/8 + 1 bytes
    sizes[1] = htonl(curv_size);

    //Allocate memory for randp_str
    randp_str = (unsigned char **)malloc(2* sizeof(unsigned char*));
    randp_size = mpz_sizeinbase(randp[0], 10)+2;
    randp_str[0] = (unsigned char *)malloc(randp_size*sizeof(unsigned char));
    sizes[2]=htonl(randp_size);

    randp_size = mpz_sizeinbase(randp[1], 10) + 2; 
    randp_str[1] = (unsigned char *)malloc(randp_size*sizeof(unsigned char));
    sizes[3]=htonl(randp_size);

    //Allocate memory for m_str
    m_size = mpz_sizeinbase(m, 10)+2;
    m_str = (unsigned char *)malloc(m_size*sizeof(unsigned char));
    sizes[4]=htonl(m_size);

    //Get string values for curv, randp, m from the corresponding mpz_t variables
    mpz_get_str((char *)curv_str[0], 10, curv[0]);
    mpz_get_str((char *)curv_str[1], 10, curv[1]);
    mpz_get_str((char *)randp_str[0], 10, randp[0]);
    mpz_get_str((char *)randp_str[1], 10, randp[1]);
    mpz_get_str((char *)m_str, 10, m);
    //sizes[0] = strlen(curv_str[0]); //variable to be sent to the server
    //sizes[1] = strlen(curv_str[1]);
   // sizes[2] = strlen(randp_str[0]); //variable to be sent to the server
    //sizes[3] = strlen(randp_str[1]);//variable to be sent to the server
    //sizes[4] = strlen(m_str); //variable to be sent to the server

    printf("curv_str[0]: %s curv_str[1]: %s\n randp_str[0]: %s randp_str[1]: %s\n m_str: %s\n\n", curv_str[0], curv_str[1], randp_str[0], randp_str[1], m_str);
    gmp_printf("curv[0]: %Zd curv[1]: %Zd\n randp[0]: %Zd randp[1]: %Zd\n m: %Zd\n\n", curv[0], curv[1], randp[0], randp[1], m);


    // socket configuration

    //socket1 = socket(AF_INET, SOCK_STREAM, 0)
    socket1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(!socket1) 
        printf("Error opening socket\n");
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(1503);
    srv_addr.sin_addr.s_addr = inet_addr(ctx_tcp->ip);

    memset(srv_addr.sin_zero, '\0', sizeof srv_addr.sin_zero); 
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(socket1, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    if(connect(socket1, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0){
        printf("Connection error!!! %s\n", strerror(errno));
        return;
    }

    /* Before the initialization request the size of the curve is sent to the server*/
    rc = send(socket1, sizes , 5 * sizeof(unsigned int), 0); //TODO: determine whether the size parameter is adequate
    if(rc <= 0){
        printf("Error sending the sizes table, %s\n", strerror(errno));
       exit(-1);
    }
    for(int i=0; i<5; i++) printf("%u\n", sizes[i]);

    /*The initialization request is (curv[0], curv[1], randp[0], randp[1], m)
    If any part of the initialiation request fails to be sent, the communication is terminated */
    //TODO: examine the possibility of using a struct for the initialization request
   // while(1==1){
        rc = send(socket1, curv_str[0], strlen(curv_str[0]), 0); //TODO: determine whether the size parameter is adequate
        if(rc <= 0){
            printf("Error sending the first curve parameter, %s\n", strerror(errno));
            exit(-1);
        }
        rc = send(socket1, curv_str[1], strlen(curv_str[1]), 0); 
        if(rc <= 0){
            printf("Error sending the second curve parameter, %s\n", strerror(errno));
            exit(-1);
        }
        rc = send(socket1, randp_str[0], strlen(randp_str[0]), 0);
        if(rc <= 0){
            printf("Error sending the first point parameter, %s\n", strerror(errno));
            exit(-1);
        }
        rc = send(socket1, randp_str[1], strlen(randp_str[1]), 0);
        if(rc <= 0){
            printf("Error sending the second point parameter, %s\n", strerror(errno));
            exit(-1);
        }
        rc = send(socket1, m_str, strlen(m_str), 0);
        if(rc <= 0){
            printf("Error sending the curve order, %s\n", strerror(errno));
            exit(-1);
        }

        /*rc = recv(socket1, message, strlen(message), 0);
        if(strcmp(message, "OK") == 0){
            printf("message %s\n", message);
            break;
        }
        else if(strcmp(message, "RESEND") == 0){ 
            printf("message %s\n", message);
            continue;
        }
    }*/
//----------------------------------------Phase 1---------------------------------------------------- 
    //mpz_urandomb(random_a, stat, 100); // a large, random number is generated
    mpz_urandomm(random_a, stat, m);
    //TODO: check whether the status var is initialized
    mpz_mul(random_A[0], random_a, randp[0]); // A = a*P(modn)
    mpz_mul(random_A[1], random_a, randp[1]);
    
    gmp_printf("A[0] = %Zd\n", random_A[0]);
    gmp_printf("A[1] = %Zd\n", random_A[1]);
    

    B_point_str = (unsigned char **)malloc(2*sizeof(char));

    rc = recv(socket1, &temp_size1, sizeof(unsigned int), 0);//receiving the actual sizes of B_point in order to allocate adequate space
    if(rc <= 0){
        printf("Error receiving the first B_point size, %s\n", strerror(errno));
        exit(-1);
    }else{ 
       temp_size1 = ntohl(temp_size1);
       printf("rc = %ld, temp_size1 = %ld\n", rc, temp_size1 );
    }

    rc = recv(socket1, &temp_size2, sizeof(unsigned int), 0);
    if(rc <= 0){
        printf("Error receiving the second B_point size, %s\n", strerror(errno));
        exit(-1);
    }else{ 
        temp_size2=ntohl(temp_size2);
        printf("rc = %ld, temp_size2 = %ld\n", rc, temp_size2 );
    }

   
    B_point_str[0] = (unsigned char *)malloc(temp_size1);
    B_point_str[1] = (unsigned char *)malloc(temp_size2);

    rc = recv(socket1, B_point_str[0], temp_size1*sizeof(unsigned char), 0);
    if(rc <= 0){
        printf("Error receiving the first B_point parameter, %s\n", strerror(errno));
        exit(-1);
    }else { /*it is possible that more data than necessary are received - in that case place the '\0' char in the correct position 
    (rc-1 or temp_size1-1) to keep only the needed data*/
        printf("rc = %ld, B_point_str[0]: %s\n", rc, B_point_str[0] );
        B_point_str[0][rc] = '\0';
        printf("New B_point_str[0] size = %ld\n", strlen((const char*)B_point_str[0]));

    }

    rc = recv(socket1, B_point_str[1], temp_size2*sizeof(unsigned char), 0);
    if(rc <= 0){
        printf("Error receiving the second B_point parameter, %s\n", strerror(errno));
        exit(-1);
    }else printf("rc = %ld, B_point_str[1]: %s\n", rc, B_point_str[1] );
    B_point_str[1][rc] = '\0';

    do{
        printf("Converting B_point coordinates to numbers...\n");
        mpz_set_str(B_point[0], (char *)B_point_str[0], 10);
        mpz_set_str(B_point[1], (char *)B_point_str[1], 10);//TODO: USE 10 AS BASE IN EVERY mpz_set_str
    }while(B_point[0]==0 || B_point[1]==0);

    gmp_printf("Succesful conversion of B_point parameters to mpz\n B_point[0]: %Zd\n B_point[1]: %Zd\n\n", B_point[0], B_point[1]);
//------------------------------------------Phase 2-----------------------------------------------------
    mpz_set_ui(m, 0);
    mpz_set_str(m, m_str, 10);

    mpz_mul(at[0], random_a, B_point[0]);
    gmp_printf("a*B[0] = %Zd\n", at[0]);
    
    mpz_mul(at[1], random_a, B_point[1]);
    gmp_printf("a*B[1] = %Zd\n", at[1]);

    mpz_set_str(pass_n, pass, 10); //convert password to mpz_t value
    mpz_tdiv_r(pw, pass_n, m);//W = Pw mod n

    gmp_printf("The client password is : %Zd\n", pw);

    mpz_mul(u[0], pw, at[0]);// u = (W*Xa+Ya)modn
    gmp_printf("pw = %Zd\n", pw);
    gmp_printf("at[0] = %Zd\n", at[0]);
    gmp_printf("m = %Zd\n", m);
    gmp_printf("The multiplication result = %Zd\n", u[0]);
    mpz_add(u[1], u[0], at[1]);
    gmp_printf("The addition result = %Zd\n", u[1]);
    mpz_mod(u[1], u[1], m);
    gmp_printf("Succesfully computed u = (W*Xa+Ya)modn = %Zd\n", u[1]);

    mpz_mul(U[0], u[1], randp[0]); //U=u*P
    mpz_mul(U[1], u[1], randp[1]);
    // check all the multiplications, if the multiplication modulus n is correct

    gmp_printf("Succesfully computed U=u*P - U[0]= %Zd, U[1]= %Zd\n\n", U[0], U[1]);


    A_str = (unsigned char **)malloc(2*sizeof(char));
    randp_size = mpz_sizeinbase(random_A[0],10) + 2;
    A_str[0] = (unsigned char *)malloc(randp_size*sizeof(char));
    randp_size = mpz_sizeinbase(random_A[1],10) + 2;
    A_str[1] = (unsigned char *)malloc(randp_size*sizeof(char));

    U_str = (unsigned char **)malloc(2*sizeof(char));
    randp_size = mpz_sizeinbase(U[0],10) + 2;
    U_str[0] = (unsigned char *)malloc(randp_size*sizeof(char));
    randp_size = mpz_sizeinbase(U[1],10) + 2;
    U_str[1] = (unsigned char *)malloc(randp_size*sizeof(char));


    mpz_get_str(A_str[0], 10, random_A[0]);
    mpz_get_str(A_str[1], 10, random_A[1]);

    mpz_get_str(U_str[0], 10, U[0]);
    mpz_get_str(U_str[1], 10, U[1]);

    //Setting the sizes table with the A and U sizes

    sizes[0] = htonl(mpz_sizeinbase(random_A[0],10) + 2);
    randp_size = mpz_sizeinbase(random_A[0],10) + 2;
    A_str[0][randp_size-1] = '\0';
    sizes[1] = htonl(mpz_sizeinbase(random_A[1],10) + 2);
    randp_size = mpz_sizeinbase(random_A[1],10) + 2;
    //rc = send(socket1, randp_size, sizeof(size_t), 0);
    A_str[1][randp_size-1] = '\0';

    sizes[2] = htonl(mpz_sizeinbase(U[0],10) + 2);
    randp_size = mpz_sizeinbase(U[0],10) + 2;
    U_str[0][randp_size-1] = '\0';
    sizes[3] = htonl(mpz_sizeinbase(U[1],10) + 2);
    randp_size = mpz_sizeinbase(U[1],10) + 2;
    U_str[1][randp_size-1] = '\0';
    sizes[4] = 0;

    rc = send(socket1, sizes, 5* sizeof(unsigned int), 0); //TODO: determine whether the size parameter is adequate
    if(rc <= 0){
        printf("Error sending the sizes table, %s\n", strerror(errno));
    exit(-1);
    }else printf("Sizes sent\n");

    rc = send(socket1, A_str[0], strlen(A_str[0]), 0); //TODO: determine whether the size parameter is adequate
    if(rc <= 0){
        printf("Error sending the first A parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("rc = %ld bytes, A_str[0] = %s\n", rc, A_str[0]);
//-----------------------------------------------------------------------------------------------------------------
    rc = send(socket1, A_str[1], strlen(A_str[1]), 0); //TODO: determine whether the size parameter is adequate
    if(rc <= 0){
        printf("Error sending the second A parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("rc = %ld bytes, A_str[1] = %s\n", rc, A_str[1]);
//----------------------------------------------------------------------------------------------------------------
   randp_size = mpz_sizeinbase(U[0],10) + 2;
   /*  rc = send(socket1, &randp_size, sizeof(randp_size), 0); //TODO: determine whether the size parameter is adequate
    if(rc <= 0){
        printf("Error sending the first U size parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("U_str[0] size = %d\n", randp_size);*/

    rc = send(socket1, U_str[0], strlen(U_str[0]), 0); //TODO: determine whether the size parameter is adequate
    if(rc <= 0){
        printf("Error sending the first U parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("rc = %ld bytes, U_str[0] = %s\n", rc, U_str[0]);
//----------------------------------------------------------------------------------------------------------------
    randp_size = mpz_sizeinbase(U[1],10) + 2;
    /*rc = send(socket1, &randp_size, sizeof(randp_size), 0); //TODO: determine whether the size parameter is adequate
    if(rc <= 0){
        printf("Error sending the second U size parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("U_str[1] size = %d\n", randp_size);*/

    rc = send(socket1, U_str[1], strlen(U_str[1]), 0); //TODO: determine whether the size parameter is adequate
    if(rc <= 0){
        printf("Error sending the second U parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("rc = %ld bytes, U_str[1] = %s\n", rc, U_str[1]);

//Phase 3 - Key Establishment 

    random_a_size = mpz_sizeinbase(random_a, 10) + 2; 
    

    random_a_str = (char*)malloc(sizeof(char)*random_a_size);

    at_str = (unsigned char**)malloc(sizeof(char*)*2); //Allocating space for the string representation of a = random_a*B
    at_size = mpz_sizeinbase(at[0], 10) + 2;
    at_str[0] = (unsigned char*)malloc(sizeof(char)*at_size);
    at_size = mpz_sizeinbase(at[1], 10) + 2;
    at_str[1] = (unsigned char*)malloc(sizeof(char)*at_size);
    printf("Allocated space for the string representation of a = random_a*B\n");


    hashcode = (unsigned char**)malloc(sizeof(char*)*2); //Allocating space for the resulting hash of RMD
    hashcode[0] = (unsigned char*)malloc(sizeof(char)*32);
    hashcode[1] = (unsigned char*)malloc(sizeof(char)*32);
    printf("Allocated space for the resulting hash of RMD\n");
    mpz_get_str(random_a_str, 10, random_a);

    mpz_get_str((char *)at_str[0], 10, at[0]); //Acquiring the string representation of the point
    mpz_get_str((char *)at_str[1], 10, at[1]);

    printf("Acquired the string representation of the point\n");
    at_size = strlen((const char*)at_str[0]); //get the actual size of the string representation of at
    at_str[0][at_size]= '\0';// assigning the last char of the strings to \0 for the needs of the RMD function
    //------------------------DEBUG--------------------------------
    printf("at_size: %ld\n", at_size );
    //-------------------------------------------------------------
   // RMD(at_str[0], at_size, hashcode[0]); // Ya = h(α) = RMD(α) = RMD(a*B)

    sha256_init(&ctx1);
    sha256_update(&ctx1, at_str[0], strlen(at_str[0]));
    sha256_final(&ctx1, hashcode[0]);
    hashcode[0][31] = '\0';
    

    printf("hashcode[0] - size: %ld\n", strlen((const char*)hashcode[0]));
    for(unsigned int i=0; i<strlen((const char*)hashcode[0]); i++){
        printf("%u ",hashcode[0][i]);
    }
    printf("\n");

    at_size = strlen((const char*)at_str[1]); //get the actual size of the string representation of at
    at_str[1][at_size]= '\0';

    //------------------------DEBUG--------------------------------
    printf("at_size: %ld\n", at_size );
    //-------------------------------------------------------------

    //RMD(at_str[1], at_size, hashcode[1]);

    sha256_init(&ctx1);
    sha256_update(&ctx1, at_str[1], strlen(at_str[1]));
    sha256_final(&ctx1, hashcode[1]);
    hashcode[1][31] = '\0';
    printf("hashcode[1] - size: %ld\n", strlen((const char*)hashcode[1]));
    for(unsigned int i=0; i<strlen((const char*)hashcode[1]); i++){
        printf("%u ", hashcode[1][i] );
    }
    printf("\n");
        

    //----------------------Receiving the h(β) from client in order to authenticte them-----------------------
    
    //Yb_size = strlen(hashcode[0]);
    memset(sizes, 0, 5*sizeof(char));// set sizes table to 0 in order to receive hashcode sizes
    rc = recv(socket1, auth_msg, 2*sizeof(char), 0); //received sizes of the hashcode
    if(rc <= 0){
        printf("Error receiving the sizes table, %s\n", strerror(errno));
    exit(-1);
    }else printf("Received the authentication result: %s\n", auth_msg);


    if(strncmp(auth_msg, "AU", 2) == 0) printf("Continuing..\n");
    else{
        printf("Authentication failed. Exiting...\n");
        exit(-1);
    }


    Yb_str = (unsigned char**)malloc(sizeof(char*)*2);
    Yb_str[0] = (unsigned char*)malloc(32);
    Yb_str[1] = (unsigned char*)malloc(32);

    rc = recv(socket1, Yb_str[0], 32*sizeof(unsigned char), 0);
    if(rc <= 0){
        printf("Error receiving the first parameter, %s\n", strerror(errno));
    exit(-1);
    }else { 
        printf("Received the first Yb parameter - size: %d ", rc);
        printf("%s\n ", Yb_str[0] );
        for(unsigned int i=0; i<32; i++){
            printf("%u ", Yb_str[0][i] );
            if(Yb_str[0][i]==hashcode[0][i]) //if each received char is equal to the hashcode[0] equivalent, keep auth1 = 1
                auth1 = 1; 
            else 
                auth1 = 0; // if at least one char is different, set auth1 = 0, so that the authentication fails
        }
        printf("\n");
    }

    rc = recv(socket1, Yb_str[1], 32*sizeof(unsigned char), 0);
    if(rc <= 0){
        printf("Error receiving the second parameter, %s\n", strerror(errno));
    exit(-1);
    }else{ 
        printf("Received the second Yb parameter- size: %d ", rc);
        printf("%s\n ", Yb_str[1] );
        for(unsigned int i=0; i<32; i++){
            printf("%u ", Yb_str[1][i] );
            if(Yb_str[1][i]==hashcode[1][i]) //if each received char is equal to the hashcode[1] equivalent, keep auth2 = 1
                auth2 = 1; 
            else 
                auth2 = 0; // if at least one char is different, set auth2 = 0, so that the authentication fails
        }
        printf("\n");
    }

    if(auth1 == 1 &&  auth2 == 1){

        rc = send(socket1, "AU", 2, 0); //send the size of the hashcode to the client
        if(rc <= 0){
            printf("Error sending authentication result %s\n", strerror(errno));
            exit(-1);
        }else printf("Sent result: %ld bytes\n", rc);


        printf("Authenticated!!!");

        u_size = mpz_sizeinbase(u[1], 10)+2; //size in characters

        u_str = (char*)malloc(u_size*sizeof(char));

        mpz_get_str(u_str, 10, u[1]);
        printf("u_str: %s\n", u_str);

        size_t temp_size = strlen((const char*)U_str[0])+strlen((const char*)U_str[1])+64*sizeof(char)+strlen((const char*)u_str);
        //the size of the final key is equal to the sum of the sizes of its parts
        temp_str = (unsigned char*)malloc(temp_size);
        // Use the string versions of the respective IDs  to generate the shared session key
        snprintf(temp_str, temp_size, "%s%s%s%s%s", U_str[0], U_str[1], Yb_str[0], Yb_str[1], u_str);
        printf("U_str[0]: %ld\nU_str[1]:%ld\nhashcode[0]:%ld\nhashcode[1]:%ld\nv_str:%ld\n", strlen((const char*)U_str[0]),strlen((const char*)U_str[1]), strlen((const char*)hashcode[0]), strlen((const char*)hashcode[1]), strlen((const char*)u_str));
        temp_str[temp_size-1] = '\0';
        printf("temp_str length  = %ld\n", strlen((const char*)temp_str));

     printf("The temp_str is:\n");
        for(int i=0; i<strlen((const char*)temp_str); i++) printf("%u ", temp_str[i]);
        printf("\n");
        printf("\n");

        temp_size = strlen((const char*)temp_str);
        //printf("temp_str length: %ld\ntemp_size: %ld\n",strlen((const char*)temp_str), temp_size);
        //RMD(temp_str, (unsigned long)temp_size, finalkey); //sometimes temp_size <> strlen(temp_str), and if the first one is used the final key is not
        sha256_init(&ctx1);
        sha256_update(&ctx1, temp_str, strlen(temp_str));
        sha256_final(&ctx1, finalkey);
        //computed correctly

        //finalkey[31] = '\0'; 
        unsigned char temp[32];
        for(int i=0; i<strlen((const char*)finalkey); i++){
            printf("%u ", finalkey[i]);
            temp[i] = finalkey[i];
            //printf(" - %u ", temp[i]);
        }
        printf("\n");
        char ch1[33];
        int index = 0;
        for(int i=0; i<strlen(finalkey); i++){
            index += sprintf(&ch1[index], "%u", temp[i]);
        }
        printf("%s\n", ch1 );
        //finalkey_v2[31] = '\0';
        printf("finalkey_v2 = %s\n", finalkey_v2 );
        printf("\n");
        ch1[32] = '\0';
    printf("------DEBUG----------------------------------\n");
    //printf("The final key is:\n");
    //for(unsigned int i=0; i<temp_size; i++) printf("%u ", finalkey[i]);
    //printf("The final key size is %ld\n", strlen((const char*)finalkey));
    printf("\n");
    //finalkey[31] = '\0'; //set the last byte of finalkey to null

    if(close(socket1)<0)
    perror("Error closing socket!");


    int result = mpz_set_str(ctx->shared_key[0], ch1, 0);
    printf("mpz_set_str returned: %d\n", result);
    gmp_printf("ctx->shared_key[0] = %Zd\n", ctx->shared_key[0]);
    return 0;
    }else{ 
    printf("Authentication failed\n");
    rc = send(socket1, "NO", 2, 0); //send the size of the hashcode to the client
    if(rc <= 0){
        printf("Error sending authentication result %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent result: %ld bytes\n", rc);
    
    if(close(socket1)<0)
        perror("Error closing socket!");
    return -1;
    }
    

}


int _modbus_fs_aka_server(modbus_t *ctx){

    //Initialization Phase
    int socket1, socket2, received;
    int i;
    unsigned char **curv_str, **randp_str, **A_str, **U_str, **B_point_str, **vita_str;
    char *m_str, *v_str;
    unsigned char **hashcode,*temp_str, finalkey[32], *res_str;
    char cl_pass[] = "123456";
    char message[6];
    char auth_msg[2];
    ssize_t rc, size;
    unsigned int sizes[5];
    size_t temp1 = 80;
    socklen_t clilen;
    unsigned int temp_size;
    struct timeval tv;

    struct sockaddr_in srv_addr, cl_addr;
    SHA256_CTX ctx1;

    mpz_t m, random_b, W;
    mpz_t curv[2];
    mpz_t randp[2];
    mpz_t B_point[2];
    mpz_t A[2], U[2];
    mpz_t vita[2]; 
    mpz_t temp;
    mpz_t v[2]; mpz_t V[2];
    mpz_t cl_pass_n;


    mpz_init(m);
    mpz_init(curv[0]);
    mpz_init(curv[1]);
    mpz_init(randp[0]);
    mpz_init(randp[1]);
    mpz_init(random_b);
    mpz_init(W);
    mpz_init(B_point[0]); mpz_init(B_point[1]);
    mpz_init(A[0]); mpz_init(A[1]);
    mpz_init(U[0]); mpz_init(U[1]);
    mpz_init(vita[0]); mpz_init(vita[1]);
    mpz_init(temp);
    mpz_init(v[0]); mpz_init(v[1]); mpz_init(V[0]); mpz_init(V[1]);
    mpz_init(cl_pass_n);

     gmp_randinit(stat, GMP_RAND_ALG_LC, 120);

    // socket configuration
    //socket1 = socket(AF_INET, SOCK_STREAM, 0);
    socket1 = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(!socket1) 
        printf("Error opening socket\n");
    bzero( &srv_addr, sizeof( srv_addr ) );


    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(1503);
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    memset(srv_addr.sin_zero, '\0', sizeof srv_addr.sin_zero); 
    int on = 1;
    setsockopt (socket1, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));

    if(bind(socket1, (struct sockaddr*) &srv_addr, sizeof(srv_addr))<0) {
        perror("Error on binding\n");
        return;
    }

    if((listen(socket1,1)) == 0) //on succesful return
        printf("Listening...\n");
    else {
        printf("Listen error: %s\n", strerror(errno));
        return;
    }
    clilen = sizeof(cl_addr);
    socket2 = accept(socket1, (struct sockaddr *)&cl_addr, (socklen_t *) &clilen);
    if(socket2>0) printf("Accepted a new connection\n");

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(socket2, SOL_SOCKET, SO_RCVTIMEO,(const char*)&tv, sizeof(tv));


    /* Before receiving the parameters that the client has chosen, the sizes of those parameters are received in order to allocate the
    required space in memory*/
    rc = recv(socket2, sizes, 5 * sizeof(int), 0);
    if(rc <= 0){
        printf("Error receiving sizes table %s\n", strerror(errno));
        exit(-1);
    } else printf("Received sizes\n");

    for(int i=0; i<5; i++) {
        sizes[i]-=2;
        printf("%d ", sizes[i] );
    }
    printf("\n");

    curv_str = (unsigned char**)malloc(2*sizeof(char*));
    curv_str[0] = (unsigned char*)malloc(sizes[0]);
    curv_str[1] = (unsigned char*)malloc(sizes[1]);

    randp_str = (unsigned char**)malloc(2*sizeof(char*));
    randp_str[0] = (unsigned char*)malloc(sizes[2]);
    randp_str[1] = (unsigned char*)malloc(sizes[3]);

    m_str = (unsigned char*)malloc(sizes[4]);

    /* Receiving the initialization request (curv[0], curv[1], randp[0], randp[1], m*/
    //do{
        rc = recv(socket2, curv_str[0], sizes[0]*sizeof(unsigned char), 0);
        if(rc <= 0){
            printf("Error receiving the first curve parameter, %s\n", strerror(errno));
            exit(-1);
        } else{ 
            printf("Received curv_str[0]: %s - size = %ld expected size = %ld\n",curv_str[0], strlen((const char*)curv_str[0]), sizes[0] );
            //if(rc < sizes[0]) exit(-1);
        }

        rc = recv(socket2, curv_str[1], sizes[1]*sizeof(unsigned char), 0);
        if(rc <= 0){
            printf("Error receiving the second curve parameter, %s\n", strerror(errno));
            exit(-1);
        }else{
            printf("Received curv_str[1]: %s - size = %ld expected size = %ld\n", curv_str[1], strlen((const char*)curv_str[1]), sizes[1]);
            //if(rc < sizes[1]) exit(-1);
        }

        rc = recv(socket2, randp_str[0], sizes[2]*sizeof(unsigned char), 0);
        if(rc <= 0){
            printf("Error receiving the first randp parameter, %s\n", strerror(errno));
            exit(-1);
        }else {
            printf("Received randp_str[0]: %s - size = %ld expected size = %ld\n",randp_str[0], strlen((const char*)randp_str[0]), sizes[2]);
            //if(rc < sizes[2]) exit(-1);
        }

        rc = recv(socket2, randp_str[1], sizes[3]*sizeof(unsigned char), 0);
        if(rc <= 0){
            printf("Error receiving the second randp parameter, %s\n", strerror(errno));
            exit(-1);
        }else{ 
            printf("Received randp_str[1]: %s - size = %ld expected size = %ld\n",randp_str[1], strlen((const char*)randp_str[1]), sizes[3]);
            //if(rc < sizes[3]) exit(-1);
        }

        rc = recv(socket2, m_str, sizes[4]*sizeof(unsigned char), 0);
        if(rc <= 0){
            printf("Error receiving the m_str parameter, %s\n", strerror(errno));
            exit(-1);
        }else {
            printf("Received m_str: %s - size = %ld expected size = %ld\n",m_str, strlen((const char*)m_str), sizes[4]);
            //if(rc < sizes[4]) exit(-1);
        }
        /*if(strlen(curv_str[0]) < sizes[0] || (strlen(curv_str[1]) < sizes[1] || (strlen(randp_str[0]) < sizes[2] || (strlen(randp_str[1]) < sizes[3] || strlen(m_str) < sizes[4])))){
            printf("Error receiving the parameters, trying again...\n");
            received = -1;
            strcpy(message,"RESEND");
            rc = send(socket2, message, strlen(message), 0);
        }else{
            printf("Received the correct parameters, resuming key exchange.\n");
            received = 0;
            strcpy(message,"OK");
            rc = send(socket2, message, strlen(message), 0);
        }*/
        
    //}while(received!=0);

    // Get the multiple precision numbers from the strings 
    i=0;
    do{
        i++;
        printf("Converting the parameters...\n");
        mpz_set_str(curv[0], curv_str[0], 10);
        mpz_set_str(curv[1], curv_str[1], 10);
        mpz_set_str(randp[0], randp_str[0], 10);
        mpz_set_str(randp[1], randp_str[1], 10);
        mpz_set_str(m, m_str, 10);

        if(i==10) exit(-1); //if the parameters were not decoded correcly exit the program
    }while(mpz_cmp_ui(curv[0], 0)==0 || (mpz_cmp_ui(curv[1], 0)==0 || (mpz_cmp_ui(randp[0],0)==0 || (mpz_cmp_ui(randp[1],0)==0 || mpz_cmp_ui(m, 0)==0))));

    gmp_printf("curv[0]: %Zd curv[1]: %Zd\n randp[0]: %Zd randp[1]: %Zd\n m: %Zd\n\n", curv[0], curv[1], randp[0], randp[1], m);

    // Phase 1 
    mpz_urandomm(random_b, stat, m); //select a random number 0<random_b<m-1
    gmp_printf("Generated random_b: %Zd\n ", random_b);

    mpz_set_str(cl_pass_n, cl_pass, 10); //converting client password to mpz_t value
    mpz_tdiv_r(W, cl_pass_n, m); //W = password%m
    gmp_printf("The client password is : %Zd\n", W);

    size_t randp_size=mpz_sizeinbase(randp[0], 10) +2;

    mpz_add(temp, random_b, W); //B = (b+W)*P
    mpz_mul(B_point[0], temp, randp[0]);
    mpz_mul(B_point[1], temp, randp[1]);

    gmp_printf("Calculated B_point[0] = %Zd, B_point[1] = %Zd\n", B_point[0], B_point[1]);

    B_point_str = (char **)malloc(2*sizeof(char*));

    temp_size = mpz_sizeinbase(B_point[0], 10) +2; //get the actual size of B_point in chars and use it to allocate space and send it to client
    B_point_str[0] = (char *)malloc(temp_size*sizeof(char));
    rc = send(socket2, &temp_size, sizeof(temp_size), 0);
    if(rc <= 0){
       printf("Error sending the first B_point size, %s\n", strerror(errno));
       exit(-1);
    }else printf("Sent B_point- size = %ld bytes\n", rc);

    temp_size = mpz_sizeinbase(B_point[1], 10) +2; //get the actual size of B_point in chars and use it to allocate space
    B_point_str[1] = (char *)malloc(temp_size*sizeof(char));
    rc = send(socket2, &temp_size, sizeof(temp_size), 0);
    if(rc <= 0){
        printf("Error sending the second B_point size, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent B_point - size = %ld bytes\n", rc);

    mpz_get_str(B_point_str[0], 10, B_point[0]);
    mpz_get_str(B_point_str[1], 10, B_point[1]);

    //B_point_str[0][69] = '\0';
    //B_point_str[1][69] = '\0';

    printf("B_point_str[0] = %s\n", B_point_str[0]);
    printf("B_point_str[1] = %s\n", B_point_str[1]);

    temp_size = mpz_sizeinbase(B_point[0], 10) + 2 ; //get the actual size of the string

    rc = send(socket2, B_point_str[0], temp_size*sizeof(unsigned char), 0);
    if(rc <= 0){
        printf("Error sending the first B_point parameter, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent B_point_str[0] - size = %ld bytes\n", rc);

    temp_size = mpz_sizeinbase(B_point[1], 10) + 2;//get the actual size of the string


    rc = send(socket2, B_point_str[1], temp_size*sizeof(unsigned char), 0);
    if(rc <= 0){
        printf("Error sending the second B_point parameter, %s\n", strerror(errno));
        exit(-1);
    }else printf("Sent B_point_str[1] - size = %ld bytes\n", rc);
    // Phase 2

    //Receive the sizes of the points first
    memset(sizes, 0, 5*sizeof(char));

    temp1 = mpz_sizeinbase(randp[0], 10) + 2;

    rc = recv(socket2, sizes, 5*sizeof(unsigned int), 0);
    if(rc <= 0){
    printf("Error receiving the sizes table, %s\n", strerror(errno));
    exit(-1);
    }else printf("Received sizes table\n");

    for(int i=0; i<4; i++) sizes[i]-=2;

    A_str = (unsigned char **)malloc(2*sizeof(char));
    A_str[0] = (unsigned char *)malloc(sizes[0]*sizeof(char));
    A_str[1] = (unsigned char *)malloc(sizes[1]*sizeof(char));

    U_str = (unsigned char **)malloc(2*sizeof(char));
    U_str[0] = (unsigned char *)malloc(sizes[2]*sizeof(char));
    U_str[1] = (unsigned char *)malloc(sizes[3]*sizeof(char));


    rc = recv(socket2, A_str[0], sizes[0]*sizeof(unsigned char), 0); 
    if(rc <= 0){
        printf("Error receiving the first A parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("Received A_str[0]: %s\n - size = %ld\n", A_str[0], rc);
    A_str[0][sizes[0]] = '\0';
//---------------------------------------------------------------------------------------
    temp_size = 0;
    /*rc = recv(socket2, &temp_size, sizeof(temp_size), 0);
    if(rc <= 0){
    printf("Error receiving the second A size parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("Received A_str[1] size = %d\n", temp_size);*/

    rc = recv(socket2, A_str[1], sizes[1]*sizeof(unsigned char), 0);
    if(rc <= 0){
        printf("Error receiving the second A parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("Received A_str[1]: %s\n - size = %ld\n", A_str[1], rc);
    A_str[1][sizes[1]] = '\0';
//---------------------------------------------------------------------------------------
    /*rc = recv(socket2, &temp_size, sizeof(temp_size), 0);
    if(rc <= 0){
    printf("Error receiving the first U size parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("Received U_str[0] size = %ld\n", temp_size);*/

    rc = recv(socket2, U_str[0], sizes[2]*sizeof(unsigned char), 0); 
    if(rc <= 0){
        printf("Error receiving the first U parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("Received U_str[0]: %s - size = %ld\n", U_str[0], rc);
    U_str[0][sizes[3]] = '\0';
//---------------------------------------------------------------------------------------
    /*rc = recv(socket2, &temp_size, sizeof(temp_size), 0);
    if(rc <= 0){
    printf("Error receiving the second U size parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("Received U_str[1] size = %ld\n", temp_size);*/
    rc = recv(socket2, U_str[1], sizes[3]*sizeof(unsigned char), 0); 
    if(rc <= 0){
        printf("Error receiving the second U parameter, %s\n", strerror(errno));
    exit(-1);
    }else printf("Received U_str[1] %s - size = %ld\n", U_str[1], rc);
    U_str[1][sizes[3]] = '\0';

    do{
        printf("Converting A and U to numbers...\n");
        mpz_set_str(A[0], A_str[0], 10);
        mpz_set_str(A[1], A_str[1], 10);
        mpz_set_str(U[0], U_str[0], 10);
        mpz_set_str(U[1], U_str[1], 10);
    }while(A[0]==0 || (A[1]==0 || (U[0]==0 || U[1]==0)));

    gmp_printf("Succesfully converted A to mpz numbers:\n A[0] = %Zd\n A[1] = %Zd\n\n", A[0], A[1]);
    gmp_printf("Converted U_str to U[0]: %Zd\n U[1]: %Zd\n\n", U[0], U[1]);      

    //Phase 3 - Key Establishment

    mpz_add(temp, random_b, W);
    gmp_printf("(b+W) = %Zd\n", temp);

    mpz_mul(vita[0], temp, A[0]); //β = (b+W)*A
    gmp_printf("(b+W)*A[0] mod m = %Zd\n", vita[0]);

    mpz_mul(vita[1], temp, A[1]);
    gmp_printf("(b+W)*A[1] mod m = %Zd\n", vita[1]);

    gmp_printf("Calculated β - vita[0] = %Zd\n vita[1] = %Zd\n\n", vita[0], vita[1] );

    mpz_mul(v[0], W, vita[0]); //v = W*Xβ + Υβ
    gmp_printf("w = %Zd\n", W);
    gmp_printf("vita[0] = %Zd\n", vita[0]);
    gmp_printf("m = %Zd\n", m);
    gmp_printf("The multiplication result = %Zd\n", v[0]);
    mpz_add(v[1], v[0], vita[1]);
    gmp_printf("The addition result = %Zd\n", v[1]);
    mpz_mod(v[1], v[1], m);
    gmp_printf("Calculated v = %Zd\n", v[1]);

    mpz_mul(V[0], randp[0], v[1]); //V = v*P
    mpz_mul(V[1], randp[1], v[1]);

    gmp_printf("Calculated V[0] = %Zd, V[1] = %Zd\n", V[0], V[1]);

    if((mpz_cmp(V[0], U[0])== 0) && (mpz_cmp(V[1], U[1])== 0)){
        rc = send(socket2, "AU", 2, 0); //send the size of the hashcode to the client
        if(rc <= 0){
            printf("Error sending authentication result %s\n", strerror(errno));
            exit(-1);
        }else printf("Sent result: %ld bytes\n", rc);

        size = mpz_sizeinbase(vita[0], 10) + 2;
        vita_str = (unsigned char **)malloc(2*sizeof(char*)); 
        vita_str[0] = (unsigned char *)malloc(size);
        size = mpz_sizeinbase(vita[1], 10) + 2;
        vita_str[1] = (unsigned char *)malloc(size);

   
        hashcode = (unsigned char**)malloc(sizeof(char*)*2); //Allocating space for the resulting hash of RMD
        hashcode[0] = (unsigned char*)malloc(32);
        hashcode[1] = (unsigned char*)malloc(32);
        printf("Allocated space for the resulting hash of RMD\n");

        mpz_get_str(vita_str[0], 10, vita[0]); //acquire the string representation of vita
        mpz_get_str(vita_str[1], 10, vita[1]);

        size = strlen((const char*)vita_str[0]); //get the actual size of vita_str, set the last character ='\0' and produce the hashcode
        vita_str[0][size] = '\0';

        //------------------------DEBUG--------------------------------
        printf("(vita)size: %ld\n", size );
        //-------------------------------------------------------------

        //RMD(vita_str[0], (unsigned long)size, hashcode[0]);
        sha256_init(&ctx1);
        sha256_update(&ctx1, vita_str[0], strlen(vita_str[0]));
        sha256_final(&ctx1, hashcode[0]);
        printf("strlen(hashcode[0] = %d \n", strlen(hashcode[0]));
        for(int i=0; i<strlen((const char*)hashcode[0]); i++){
            printf(" %u", hashcode[0][i]);
        }
        printf("\n");

        size = strlen((const char*)vita_str[1]);
        vita_str[1][size] = '\0';
        //RMD(vita_str[1], (unsigned long)size, hashcode[1]);
        sha256_init(&ctx1);
        sha256_update(&ctx1, vita_str[1], strlen(vita_str[1]));
        sha256_final(&ctx1, hashcode[1]);
        printf("hashcode[1] - size: %ld\n", strlen(hashcode[1]));
        for(int i=0; i<strlen((const char*)hashcode[1]); i++){
            printf("%u ", hashcode[1][i] );
        }
        printf("\n");

        memset(sizes, 0, 5*sizeof(char));// Reset all values in sizes table
        sizes[0] = 32; 
        sizes[1] = 32;
        sizes[2] = 0;
        sizes[3] = 0;
        sizes[4] = 0; 

        hashcode[0][31] = '\0';
        hashcode[1][31] = '\0';

        rc = send(socket2, hashcode[0], sizes[0], 0);
        if(rc <= 0){
            printf("Error sending the first hashcode parameter, %s\n", strerror(errno));
            exit(-1);
        }else { 
            printf("Sent the first hashcode parameter:");
            for(int i=0; i<rc; i++){
                printf("%u ", hashcode[0][i] );
            }
            printf("\n");
        }

        rc = send(socket2, hashcode[1], sizes[1], 0);
        if(rc <= 0){
            printf("Error sending the second hashcode parameter, %s\n", strerror(errno));
            exit(-1);
        }else { 
            printf("Sent the second hashcode parameter:");
            for(int i=0; i<rc; i++){
                printf("%u ", hashcode[1][i] );
            }
            printf("\n");
        }

        rc = recv(socket2, auth_msg, 2*sizeof(char), 0); //received sizes of the hashcode
        if(rc <= 0){
            printf("Error receiving the authentication result, %s\n", strerror(errno));
            exit(-1);
        }else printf("Received the authentication result: %s\n", auth_msg);

        if(strncmp(auth_msg, "AU", 2) == 0) printf("Continuing..\n");
        else{
            printf("Authentication failed. Exiting...\n");
            exit(-1);
        }


        size = mpz_sizeinbase(v[1], 10)+2;
        v_str = (char*)malloc(size * sizeof(char));
        mpz_get_str(v_str, 10, v[1]);
        printf("v_str: %s\n", v_str);

        size_t temp_size = strlen((const char*)U_str[0])+strlen((const char*)U_str[1])+64*sizeof(char)+strlen((const char*)v_str);
        printf("temp_size = %ld\n", temp_size);
        //the size of the final key is equal to the sum of the sizes of its parts
        temp_str = (unsigned char*)malloc(temp_size);

        snprintf(temp_str, temp_size, "%s%s%s%s%s", U_str[0], U_str[1], hashcode[0], hashcode[1], v_str);
        printf("U_str[0]: %ld\nU_str[1]:%ld\nhashcode[0]:%ld\nhashcode[1]:%ld\nv_str:%ld\n", strlen((const char*)U_str[0]),strlen((const char*)U_str[1]), strlen((const char*)hashcode[0]), strlen((const char*)hashcode[1]), strlen((const char*)v_str));

        temp_str[temp_size-1] = '\0';

        temp_size = strlen((const char*)temp_str);
        printf("temp_str length  = %ld\n", strlen((const char*)temp_str));


        printf("The temp_str is:\n");
        for(int i=0; i<strlen((const char*)temp_str); i++) printf("%u ", temp_str[i]);
        printf("\n");

        printf("temp_str length: %ld\ntemp_size: %ld\n",strlen((const char*)temp_str), temp_size);

        //RMD(temp_str, (unsigned long)temp_size, finalkey);

        sha256_init(&ctx1);
        sha256_update(&ctx1, temp_str, strlen(temp_str));
        sha256_final(&ctx1, finalkey);
        for(int i=0; i<strlen((const char*)finalkey); i++) printf("%u ", finalkey[i]);
        printf("\n");

        unsigned int temp[32];
        for(int i=0; i<strlen((const char*)finalkey); i++){
            //printf("%u ", finalkey[i]);
            temp[i] = finalkey[i];
            //printf(" - %u ", temp[i]);
        }
        printf("\n");
        char ch1[33];
        int index = 0;
        for(int i=0; i<strlen(finalkey); i++){
            index += sprintf(&ch1[index], "%u", temp[i]);
        }
        ch1[32] = '\0';
        printf("%s\n", ch1 );

        printf("------DEBUG----------------------------------\n");
        printf("The final key size is %ld\n", strlen((const char*)finalkey));
        finalkey[strlen((const char*)finalkey)] = '\0'; //set the last byte of finalkey to null
        //printf("The final key is:\n");
        //for(int i=0; i<temp_size; i++) printf("%u ", finalkey[i]);
        printf("\n");
        if(close(socket1)<0)
            perror("Error closing socket!");
        mpz_set_str(ctx->shared_key[0], ch1, 10);
        gmp_printf("ctx->shared_key[0] = %Zd\n", ctx->shared_key[0]);


        return 0;
    }else{ 
        printf("Authentication not succesful\n");
        rc = send(socket2, "NO", 2, 0); //send the size of the hashcode to the client
        if(rc <= 0){
            printf("Error sending authentication result %s\n", strerror(errno));
        }else printf("Sent result: %ld bytes\n", rc);
        
        exit(-1);
    }

}

//-----------------------helper function to convert sizes to big endian----------------------------------

unsigned int reverseSize (unsigned int i) {
    unsigned char c1, c2, c3, c4;

        c1 = i & 255;
        c2 = (i >> 8) & 255;
        c3 = (i >> 16) & 255;
        c4 = (i >> 24) & 255;

        return ((unsigned int)c1 << 24) + ((unsigned int)c2 << 16) + ((unsigned int)c3 << 8) + c4;
}