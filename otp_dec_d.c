#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead, charsSent;
	socklen_t sizeOfClientInfo;
	char buffer[1001];
	struct sockaddr_in serverAddress, clientAddress;
    char* verificationMsgIn = "otp_dec";        // Message to be received from the client
    char* passMsg = "PASS";                     // Message confirming verification to the client
    char* failMsg = "FAIL";                     // Message denying verificcation to the client
    int checkSend = -5;
    char* inMessage;
    char* cipherMessage;
    char* keyMessage;
    char* plainMessage;
    char* outMessage;
    int lineSize;
    int bytesRead = 0;
    pid_t childPid = -10;
    int exitStatus;

    // Check usage & args
	if (argc < 2)
    {
        fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1);
    }

	// Set up the address struct for this process (the server)
    // Clear out the address struct
	memset((char *)&serverAddress, '\0', sizeof(serverAddress));

    // Get the port number, convert to an integer from a string
	portNumber = atoi(argv[1]);

    // Create a network-capable socket
	serverAddress.sin_family = AF_INET;

    // Store the port number
	serverAddress.sin_port = htons(portNumber);

    // Any address is allowed for connection to this process
	serverAddress.sin_addr.s_addr = INADDR_ANY;

	// Set up the socket
    // Create the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
	if (listenSocketFD < 0) 
    {
        fprintf(stderr, "DAEMON: ERROR  - Open failure with socket %s.\n", argv[1]);
        exit(1);
    }

	// Enable the socket to begin listening
    // Connect socket to port
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        fprintf(stderr, "DAEMON: ERROR - Unable to bind socket %s.\n", argv[1]);
        exit(1);
    }

    // Flip the socket on - it can now receive up to 5 connections
	listen(listenSocketFD, 5);

	while(1)
    {
        // Accept a connection, blocking if one is not available until one connects
        // Get the size of the address for the client that will connect
        sizeOfClientInfo = sizeof(clientAddress);

        // Accept
        establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);

        //If there's an error with accepting a connection
        if (establishedConnectionFD < 0)
        {
            fprintf(stderr, "DAEMON: ERROR - accept failure.\n");
        }

        // Create child process with successful connection
        childPid = fork();

        // If child successfully formed
        if (childPid == 0)
        {

            /*************************************************************************/
            // GETTING THE VERIFICATION MESSAGE FROM THE CLIENT
            /*************************************************************************/

            charsRead = recv(establishedConnectionFD, &lineSize, sizeof(lineSize), 0);
            if (charsRead < 0)
            {
                fprintf(stderr, "DAEMON: ERROR - Socket read failure.\n");
            }


            // Allocate the memory for complete message
            inMessage = malloc((lineSize + 1) * sizeof(char));

            // Reset the buffer
            memset(inMessage, '\0', sizeof(inMessage));

            // Read from the socket until the expected amount of data is received
            while (bytesRead < lineSize)
            {
                // Reset the buffer
                memset(buffer, '\0', sizeof(buffer));

                // Read from the socket
                charsRead = recv(establishedConnectionFD, buffer, strlen(buffer) - 1, 0);

                //If there's a read error
                if (charsRead < 0)
                {
                    fprintf(stderr, "DAEMON: ERROR - Socket read failure.\n");
                    break;
                }

                // Increment bytesread
                bytesRead += charsRead;

                // Concatenate the contents of buffer to inMessage
                strcat(inMessage, buffer);
            }

            /*************************************************************************/

            /*************************************************************************/
            // CLIENT PASSES VERIFICATION
            /*************************************************************************/

            // If the correct verification was received
            if (strncmp(inMessage, verificationMsgIn, lineSize) == 0)
            {
                // Free the meory used by inMessage
                free(inMessage);
                inMessage = NULL;
                
                /*************************************************************************/
                // SEND A PASS MESSAGE TO THE CLIENT
                /*************************************************************************/

                lineSize = strlen(passMsg);  // Send the message size to the server
                charsSent = send(establishedConnectionFD, &lineSize, sizeof(lineSize), 0);  // Send the size

                //If there was an error with writing to this socket
                if (charsSent < 0) 
                {
                    fprintf(stderr, "DAEMON: ERROR - Socket write failure.\n");
                }

                charsSent = send(establishedConnectionFD, passMsg, strlen(passMsg), 0);

                //If there was an error with writing to this socket
                if (charsSent < 0) 
                {
                    fprintf(stderr, "DAEMON: ERROR - Socket write failure.\n");
                }

                /*************************************************************************/
                // GET THE CIPHER TEXT FROM THE CLIENT
                /*************************************************************************/

                // Get the message size from the client
                charsRead = recv(establishedConnectionFD, &lineSize, sizeof(lineSize), 0);
                if (charsRead < 0)
                {
                    fprintf(stderr, "DAEMON: ERROR - Socket read failure.\n");
                }

                // Allocate the memory for complete message
                cipherMessage = malloc((lineSize + 1) * sizeof(char));

                // Reset the buffer
                memset(cipherMessage, '\0', sizeof(cipherMessage));

                // Reset bytesread
                bytesRead = 0;

                // Call recv until the required number of bytes have been received
                while (bytesRead < lineSize)
                {
                    // Reset the buffer
                    memset(buffer, '\0', sizeof(buffer));

                    // Read from the socket
                    charsRead = recv(establishedConnectionFD, buffer, sizeof(buffer) - 1, 0);


                    // If there was an issue reading from the socket
                    if (charsRead < 0)
                    {
                        fprintf(stderr, "DAEMON: ERROR - Socket read failure.\n");
                    }

                    // Increment bytesRead
                    bytesRead += charsRead;

                    // Concatenate the contents of the buffer to cipherMessage
                    strcat(cipherMessage, buffer);
                }

                /*************************************************************************/

                /*************************************************************************/
                // GET THE KEY TEXT FROM THE CLIENT
                /*************************************************************************/

                // Get the message size from the client
                charsRead = recv(establishedConnectionFD, &lineSize, sizeof(lineSize), 0);

                // If there was an issue reading from the socket
                if (charsRead < 0)
                {
                    fprintf(stderr, "DAEMON: ERROR - Socket read failure.\n");
                }

                // Allocate the memory for complete message
                keyMessage = malloc((lineSize + 1) * sizeof(char));

                // Clear out keyMessage
                memset(keyMessage, '\0', sizeof(keyMessage));

                // Reset bytesRead
                bytesRead = 0;

                // Call recv until the required number of bytes have been received
                while (bytesRead < lineSize)
                {
                    // Reset the buffer
                    memset(buffer, '\0', sizeof(buffer));

                    // Read from the socket
                    charsRead = recv(establishedConnectionFD, buffer, sizeof(buffer) - 1, 0);

                    // If there was an issue reading from the socket
                    if (charsRead < 0)
                    {
                        fprintf(stderr, "DAEMON: ERROR - Socket read failure.\n");
                    }

                    // Increment bytesread
                    bytesRead += charsRead;

                    // Concatenate the contents of the buffer to keyMessage
                    strcat(keyMessage, buffer);
                }

                /*************************************************************************/

                /*************************************************************************/
                // GENERATE THE PLAIN TEXT
                /*************************************************************************/

                //Create plaintext string
                plainMessage = malloc((strlen(cipherMessage)) * sizeof(char));
                memset(plainMessage, '\0', sizeof(plainMessage));

                char ptc, ktc, cc;  //Chars for plaintext, keytext, and ciphertext
                int ptIndex, ktIndex, cyIndex;
                char decryptionArr[27] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 
                                        'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 
                                        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' '};

                for (int i = 0; i < strlen(cipherMessage); i++)
                {
                    // Get the next char from the ciphertext
                    cc = cipherMessage[i];
                    for (int j = 0; j < 27; j++)
                    {
                        if (decryptionArr[j] == cc)
                        {
                            cyIndex = j;
                        }
                    }

                    // Get the next char from the keytext
                    ktc = keyMessage[i];
                    for (int k = 0; k < 27; k++)
                    {
                        if (decryptionArr[k] == ktc)
                        {
                            ktIndex = k;
                        }
                    }

                    // Assign their sum to cyIndex
                    ptIndex = cyIndex - ktIndex;

                    // If the result is larger than the size of the encryption array
                    if (ptIndex < 0)
                    {
                        ptIndex += 27;
                    }
                    
                    //Store the resultant char in the plainMessage
                    plainMessage[i] = decryptionArr[ptIndex];
                }

                // Free the meory used by inMessage
                free(cipherMessage);
                cipherMessage = NULL;

                // Free the meory used by inMessage
                free(keyMessage);
                keyMessage = NULL;

                /*************************************************************************/


                /*************************************************************************/
                // SEND THE DECRYPTED TEXT TO THE CLIENT
                /*************************************************************************/

               lineSize = strlen(plainMessage);  // Send the message size to the server

                charsSent = send(establishedConnectionFD, &lineSize, sizeof(lineSize), 0);  // Send the size

                //If there was an error with writing to this socket
                if (charsSent < 0) 
                {
                    fprintf(stderr, "DAEMON: ERROR - Socket write failure.\n");
                }

                charsSent = send(establishedConnectionFD, plainMessage, strlen(plainMessage), 0);

               //If there was an error with writing to this socket
                if (charsSent < 0) 
                {
                    fprintf(stderr, "DAEMON: ERROR - Socket write failure.\n");
                }

                // Free the meory used by inMessage
                free(plainMessage);
                plainMessage = NULL;

                /*************************************************************************/

                exit(0);

            }

            /*************************************************************************/
            // CLIENT FAILS VERIFICATION
            /*************************************************************************/

            else
            {
                // Send a fail message to the client
                lineSize = strlen(failMsg);  // Send the message size to the server

                charsSent = send(establishedConnectionFD, &lineSize, sizeof(lineSize), 0);  // Send the size
               
                //If there was an error with writing to this socket
                if (charsSent < 0) 
                {
                    fprintf(stderr, "DAEMON: ERROR - Socket write failure.\n");
                }

                charsSent = send(establishedConnectionFD, failMsg, strlen(failMsg), 0);
               
               //If there was an error with writing to this socket
                if (charsSent < 0) 
                {
                    fprintf(stderr, "DAEMON: ERROR - Socket write failure.\n");
                }
                exit(1);
            }

            /*************************************************************************/

            // Close the existing socket which is connected to the client
            close(establishedConnectionFD);

        }

        waitpid(childPid, &exitStatus, 0);

    }

    // Close the listening socket
	close(listenSocketFD);
    
	return 0; 
}