Prime Number Testing Suite
Overview
Implementation of three different primality testing algorithms:

Miller-Rabin probabilistic test
Sieve of Eratosthenes
Sieve of Atkin

Requirements

Python 3.x
Standard libraries only (random, time, math)

Running the Program

Save the prime testing implementation as prime_test.py
Run the program:

python3 prime_checker.py
Using the Program

When prompted, select an algorithm by entering a number (1-4):

1: Miller-Rabin test
2: Sieve of Eratosthenes
3: Sieve of Atkin
4: Exit program


Enter a positive integer to test for primality

The number must be greater than 1
For practical performance, numbers should be less than 10^7 for the sieve methods



Example Usage
CopyPrime Number Testing Algorithms - Test a Single Number
1. Miller-Rabin
2. Sieve of Eratosthenes
3. Sieve of Atkin
4. Exit

Select algorithm (1-4): 1
Enter the number to test: 97

Miller-Rabin: Prime
Average Time Taken over 10 runs: 0.000123s
Notes

The Miller-Rabin test is probabilistic but extremely reliable with the default 5 rounds
The Sieve methods are deterministic but may be slower for large numbers
Each test is run multiple times to provide average execution time
The program will continue running until you select option 4 to exit

Error Handling
Both programs include error handling for:

Invalid input values
Out of range numbers
Incorrect data types

For any errors, clear error messages will be displayed, and the program will continue running.