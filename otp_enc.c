#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <sys/ioctl.h>

//Verifies if a file has valid characters or not. Returns 
int validChars(FILE* fptr)
{
    int isValid = 1;
    char c;

    while((c = fgetc(fptr)) != EOF)
    {
        if ((c <= 64 || c >= 91) && c != ' ' && c != '\n')
        {
            fclose(fptr);
            exit(1);
        }
    }

    return 1;
}

int getFileSize(FILE* fptr)
{
    int size = 0;
    char c;

    while (c = getc(fptr) != EOF)
    {
        size++;
    }
    
    return size;
}

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsSent, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[1001];
    char* verificationMsgOut = "otp_enc";
    char* inMessage;
    char* outMessage;
    int lineSize;
    int yes = 1;
    int checkSend = -5;
    int bytesRead = 0;
    FILE* plainfp = NULL;
    FILE* keyfp = NULL;
    
    /*************************************************************************/
    // CHECK USAGE AND ARGS
    /*************************************************************************/

	if (argc < 4)
    { 
        fprintf(stderr,"USAGE: %s plaintextfile keytextfile port\n", argv[0]); 
        exit(1);
    }

    /*************************************************************************/

    /*************************************************************************/
    // CHECK PLAIN TEXT AND KEY TEXT FILES FOR INVALID CHARS
    /*************************************************************************/

    //Open and check for bad chars in the keytext and plaintext files
    // printf("CLIENT: Opening: \"%s\"\n", argv[1]);
    plainfp = fopen(argv[1], "r");
    if (plainfp == NULL)
    {
        fprintf(stderr, "CLIENT: Error opening the ciphertext file.\n");
        exit(1);
    }
    validChars(plainfp);

    // printf("CLIENT: Opening: \"%s\"\n", argv[2]);
    keyfp = fopen(argv[2], "r");
    if (keyfp == NULL)
    {
        fprintf(stderr, "CLIENT: Error opening the keytext file.\n");
        exit(1);
    }
    validChars(keyfp);

    /*************************************************************************/

    /*************************************************************************/
    // CHECK THAT KEYTEXT LENGTH IS AT LEAST EQUAL TO PLAINTEXT LENGTH
    /*************************************************************************/

    fseek(plainfp, 0, SEEK_SET);    // Reset the file pointer to the beginning of the file
    fseek(keyfp, 0, SEEK_SET);      // Reset the file pointer to the beginning of the file
    int ptFileSize = getFileSize(plainfp);
    int ktFileSize = getFileSize(keyfp);
    if (ktFileSize < ptFileSize)
    {
        fclose(keyfp);
        fclose(plainfp);
        fprintf(stderr, "CLIENT: keytext is shorter than plaintext. Exiting.\n");
        exit(1);
    }

    /*************************************************************************/

    /*************************************************************************/
    // SET UP THE SERVER ADDRESS STRUCT
    /*************************************************************************/

    // Clear out the address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress));

    // Get the port number, convert to an integer from a string
    // printf("CLIENT: Attemtping to connect on port: %s\n", argv[3]);
	portNumber = atoi(argv[3]);

    // Create a network-capable socket
	serverAddress.sin_family = AF_INET;

    // Store the port number
	serverAddress.sin_port = htons(portNumber);

    // Convert the machine name into a special form of address
	serverHostInfo = gethostbyname("localhost");

	// If there's an error getting local host
	if (serverHostInfo == NULL)
    {
        fprintf(stderr, "CLIENT: ERROR - No such host.\n");
        exit(1);
    }
    // Copy in the address
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length);

    /*************************************************************************/

    /*************************************************************************/
    // SET UP THE SOCKET
    /*************************************************************************/

    // Create the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0);

	//If there's an error creating the socket
	if (socketFD < 0) 
    {
        fprintf(stderr, "CLIENT: ERROR - Socket open failure.\n");
        exit(1);
    }

    /*************************************************************************/

    /*************************************************************************/
    // CONNECT TO THE SERVER
    /*************************************************************************/

    // Connect socket to address
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
    {
        fprintf(stderr, "CLIENT: ERROR - Socket connection failure.\n");
        exit(1);
    }

    /*************************************************************************/

    /*************************************************************************/
    // SENDING THE VERIFICATION MESSAGE TO THE SERVER
    /*************************************************************************/

    // Send the message size to the server
    lineSize = strlen(verificationMsgOut);  // Get the size of the message
    // printf("CLIENT: About to send verification message of size %d\n", lineSize);
    charsSent = send(socketFD, &lineSize, sizeof(lineSize), 0);     // Send the size
    if (charsSent < 0) //If there was an error with writing to this socket
    {
        fprintf(stderr, "CLIENT: ERROR - Socket write fail.\n");
        exit(1);
    }

    charsSent = send(socketFD, verificationMsgOut, strlen(verificationMsgOut), 0);  //Send the verification message
   if (charsSent < 0) //If there was an error with writing to this socket
    {
        fprintf(stderr, "CLIENT: ERROR - Socket write fail.\n");
        exit(1);
    }

    /*************************************************************************/

    /*************************************************************************/
    // GET PASS OR FAIL MESSAGE FROM THE SERVER
    /*************************************************************************/

    //Get the size of the data about to be transmitted
    charsRead = recv(socketFD, &lineSize, sizeof(lineSize), 0);
    if (charsRead < 0) // If there was an error reading from the socket
    {
        fprintf(stderr, "CLIENT: ERROR - Socket read fail.\n");
        exit(1);
    }

    // Allocate the memory for complete message
    inMessage = malloc((lineSize + 1) * sizeof(char));
    memset(inMessage, '\0', sizeof(inMessage));

    // Reset bytesRead
    bytesRead = 0;

    // Read data from the socket, leaving \0 at end
    while (bytesRead < lineSize)
    {
        //Reset the buffer
        memset(buffer, '\0', sizeof(buffer));

        //Read from the socket
        charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0);

        //Increment bytesRead with amount of bytes received
        bytesRead += charsRead;

        //Concatenate the contents of the buffer to inMessage
        strcat(inMessage, buffer);

        //If there was an error with the recv call
        if (charsRead == -1)
        {
            fprintf(stderr, "CLIENT: ERROR - recv failure.\n");
            break;
        }
    }
    // printf("CLIENT: I received this from the server: \"%s\"\n", inMessage);

    /*************************************************************************/

    /*************************************************************************/
    // CLIENT IS VERIFIED BY THE SERVER
    /*************************************************************************/

    if (strncmp(inMessage, "PASS", lineSize) == 0)
    {
        // printf("CLIENT: I was accepted by the server!\n");

        // Free the meory used by inMessage
        free(inMessage);
        inMessage = NULL;

        /*************************************************************************/
        // SEND THE PLAIN TEXT TO THE SERVER
        /*************************************************************************/
        lineSize = 0;
        char c;
        fseek(plainfp, 0, SEEK_SET);    // Reset the file pointer to the beginning of the file

        //Send the message size to the server
        lineSize = ptFileSize - 1;
        // printf("CLIENT: About to send the plaintext of size %d\n", lineSize);
        charsSent = send(socketFD, &lineSize, sizeof(lineSize), 0);
        if (charsSent < 0) //If there was an error with writing to this socket
        {
            fprintf(stderr, "CLIENT: ERROR - Socket write fail.\n");
            exit(1);
        }

        // Block until all data is sent
        do
        {
            ioctl(socketFD, TIOCOUTQ, &checkSend);
        } while (checkSend > 0);

        // If there was an error with ioctl
        if (checkSend < 0)
        {
            fprintf(stderr, "CLIENT: ERROR - ioctl failure.\n");
        }

        // Allocate the memory for outMessage message
        outMessage = malloc((ptFileSize) * sizeof(char));
        memset(outMessage, '\0', sizeof(outMessage));

        while ((c = fgetc(plainfp)) != EOF)
        {
            strncat(outMessage, &c, 1);
        }

        // Remove the newline
        outMessage[strcspn(outMessage, "\n")] = 0;


        // Send the message to server
        charsSent = send(socketFD, outMessage, strlen(outMessage), 0);
        if (charsSent < 0) //If there was an error with writing to this socket
        {
            fprintf(stderr, "CLIENT: ERROR - Socket write fail.\n");
            exit(1);
        }

        // Block until all data is sent
        do
        {
            ioctl(socketFD, TIOCOUTQ, &checkSend);
        } while (checkSend > 0);

        // If there was an error with ioctl
        if (checkSend < 0)
        {
            fprintf(stderr, "CLIENT: ERROR - ioctl failure.\n");
        }

        // Free the meory used by outMessage
        free(outMessage);
        outMessage = NULL;

        /*************************************************************************/

        /*************************************************************************/
        // SEND THE KEY TEXT TO THE SERVER
        /*************************************************************************/
        sleep(1);   // Pause to allow server to read the plaintext
        lineSize = 0;
        fseek(keyfp, 0, SEEK_SET);    // Reset the file pointer to the beginning of the file

        //Send the message size to the server
        lineSize = ktFileSize - 1;
        // printf("CLIENT: About to send the keytext of size %d\n", lineSize);
        charsSent = send(socketFD, &lineSize, sizeof(lineSize), 0);
        if (charsSent < 0) //If there was an error with writing to this socket
        {
            fprintf(stderr, "CLIENT: ERROR - Socket write fail.\n");
            exit(1);
        }

        // Block until all data is sent
        do
        {
            ioctl(socketFD, TIOCOUTQ, &checkSend);
        } while (checkSend > 0);

        // If there was an error with ioctl
        if (checkSend < 0)
        {
            fprintf(stderr, "CLIENT: ERROR - ioctl failure.\n");
        }
        

        // Allocate the memory for outMessage message
        outMessage = malloc((ktFileSize) * sizeof(char));
        memset(outMessage, '\0', sizeof(outMessage));

        while ((c = fgetc(keyfp)) != EOF)
        {
            strncat(outMessage, &c, 1);
        }

        // Remove the newline
        outMessage[strcspn(outMessage, "\n")] = 0;


        // Send the message to server
        charsSent = send(socketFD, outMessage, strlen(outMessage), 0);
        if (charsSent < 0) //If there was an error with writing to this socket
        {
            fprintf(stderr, "CLIENT: ERROR - Socket write fail.\n");
            exit(1);
        }

        // Block until all data is sent
        do
        {
            ioctl(socketFD, TIOCOUTQ, &checkSend);
        } while (checkSend > 0);

        // If there was an error with ioctl
        if (checkSend < 0)
        {
            fprintf(stderr, "CLIENT: ERROR - ioctl failure.\n");
        }

        // Free the meory used by outMessage
        free(outMessage);
        outMessage = NULL;

        /*************************************************************************/

        /*************************************************************************/
        // GET THE CIPHER TEXT FROM THE SERVER
        /*************************************************************************/

        //Get the size of the data about to be transmitted
        charsRead = recv(socketFD, &lineSize, sizeof(lineSize), 0);
        if (charsRead < 0) // If there was an error reading from the socket
        {
            fprintf(stderr, "CLIENT: ERROR - Socket read fail.\n");
            exit(1);
        }

        // Allocate the memory for complete message
        inMessage = malloc((lineSize + 1) * sizeof(char));
        memset(inMessage, '\0', sizeof(inMessage));

        // Reset bytesRead
        bytesRead = 0;

        // Read data from the socket, leaving \0 at end
        while (bytesRead < lineSize)
        {
            //Reset the buffer
            memset(buffer, '\0', sizeof(buffer));

            //Read from the socket
            charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0);

            //Increment bytesRead with amount of bytes received
            bytesRead += charsRead;

            //Concatenate the contents of the buffer to inMessage
            strcat(inMessage, buffer);

            //If there was an error with the recv call
            if (charsRead == -1)
            {
                fprintf(stderr, "CLIENT: ERROR - recv failure.\n");
                break;
            }
        }
        // printf("CLIENT: Ciphertext message is:\n%s\n", inMessage);
        printf("%s\n", inMessage);

        // Free the meory used by inMessage
        free(inMessage);
        inMessage = NULL;

        /*************************************************************************/

    }

    /*************************************************************************/

    /*************************************************************************/
    // CLIENT IS NOT VERIFIED BY THE SERVER
    /*************************************************************************/
    else
    {
        fprintf(stderr, "CLIENT: ERROR - Invalid credentials.\n");
        fclose(keyfp);
        fclose(plainfp);
        close(socketFD);

        // Free the meory used by inMessage
        free(inMessage);
        inMessage = NULL;
        exit(1);
    }

    /*************************************************************************/
    
    // Close the files
    fclose(keyfp);
    fclose(plainfp);


    // Close the socket
	close(socketFD);

	return 0;
}