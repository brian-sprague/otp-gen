/****************************************************************
 * Author: Brian Sprague
 * File name: keygen.c
 * Description: Runs the keygen program, which takes a single
 * argyment, a number, and prints a randomly generated string,
 * with a length of the argument passed in. 
****************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main (int argc, char* argv[])
{
    int num;
    char letter;

    //Seed rand with the current time
    srand(time(0));

    //Create output that is as long as the number passed as argv[1]
    for (int i = 0; i < atoi(argv[1]); i++)
    {
        //Generate a random number from 0 to 26
        num = (rand() % 27);

        //If num is 26 then print a space
        if (num == 26)
        {
            letter = ' ';
        }

        //Otherwise add the generated number to the A character to produce another uppercase letter
        else
        {
            letter = num + 'A';
        }
        
        //Print the character to stdout
        printf("%c", letter);
    }

    //Add a newline at the end
    printf("\n");

    return 0;
}