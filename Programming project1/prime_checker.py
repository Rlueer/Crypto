import random
import time
from math import sqrt

def miller_rabin_pass(a, s, d, n):
    """
    Single pass of Miller-Rabin primality test
    """
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(s - 1):
        x = pow(x, 2, n)
        if x == 1:
            return False
        if x == n - 1:
            return True
    return False

def is_prime_miller_rabin(n, k=5):
    """
    Miller-Rabin primality test for a single number
    """
    if n in (2, 3):
        return True
    if n <= 1 or n % 2 == 0:
        return False
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        if not miller_rabin_pass(a, s, d, n):
            return False
    return True

def sieve_of_eratosthenes_single(n):
    """
    Test primality of a single number using Sieve of Eratosthenes
    """
    if n < 2:
        return False
    sieve = [True] * (n + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(sqrt(n)) + 1):
        if sieve[i]:
            for j in range(i * i, n + 1, i):
                sieve[j] = False
    return sieve[n]

def sieve_of_atkin_single(n):
    """
    Test primality of a single number using Sieve of Atkin
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    sieve = [False] * (n + 1)
    sieve[2] = sieve[3] = True
    sqrt_n = int(sqrt(n))
    for x in range(1, sqrt_n + 1):
        for y in range(1, sqrt_n + 1):
            n1 = 4 * x * x + y * y
            if n1 <= n and n1 % 12 in (1, 5):
                sieve[n1] = not sieve[n1]
            n2 = 3 * x * x + y * y
            if n2 <= n and n2 % 12 == 7:
                sieve[n2] = not sieve[n2]
            n3 = 3 * x * x - y * y
            if x > y and n3 <= n and n3 % 12 == 11:
                sieve[n3] = not sieve[n3]
    for i in range(5, sqrt_n + 1):
        if sieve[i]:
            for j in range(i * i, n + 1, i * i):
                sieve[j] = False
    return sieve[n]

def average_execution_time(func, *args, runs=10):
    """
    Measure average execution time of a function over multiple runs.
    """
    total_time = 0
    for _ in range(runs):
        start = time.perf_counter()
        result = func(*args)
        total_time += (time.perf_counter() - start)
    avg_time = total_time / runs
    return result, avg_time

def main():
    while True:
        print("\nPrime Number Testing Algorithms - Test a Single Number")
        print("1. Miller-Rabin")
        print("2. Sieve of Eratosthenes")
        print("3. Sieve of Atkin")
        print("4. Exit")
        
        choice = input("Select algorithm (1-4): ")
        if choice == '4':
            print("Exiting program. Goodbye!")
            break
        
        try:
            num = int(input("Enter the number to test: "))
            if num <= 1:
                raise ValueError("Number must be greater than 1.")
        except ValueError as e:
            print(f"Invalid input: {e}")
            continue

        runs = 10  # Number of iterations to average time
        if choice == '1':
            result, avg_time = average_execution_time(is_prime_miller_rabin, num, runs=runs)
            print(f"Miller-Rabin: {'Prime' if result else 'Composite'}")
            print(f"Average Time Taken over {runs} runs: {avg_time:.6f}s")
        
        elif choice == '2':
            result, avg_time = average_execution_time(sieve_of_eratosthenes_single, num, runs=runs)
            print(f"Sieve of Eratosthenes: {'Prime' if result else 'Composite'}")
            print(f"Average Time Taken over {runs} runs: {avg_time:.6f}s")
        
        elif choice == '3':
            result, avg_time = average_execution_time(sieve_of_atkin_single, num, runs=runs)
            print(f"Sieve of Atkin: {'Prime' if result else 'Composite'}")
            print(f"Average Time Taken over {runs} runs: {avg_time:.6f}s")

if __name__ == "__main__":
    main()
