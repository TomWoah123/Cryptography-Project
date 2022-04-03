"""
This project is used to code the Euclidean and Extended Euclidean Algorithms for Cryptography.

Author: Timothy Wu
PID: wutp20
Date: 1/26/2022
"""


def euclidean_algorithm(a: int, n: int) -> int:
    """
    This method returns the greatest common denominator (gcd) between two integers, a and n, where n > a.
    It will repeatedly divide n and a until the remainder is 0.
    :param a: The smaller number.
    :param n: The bigger number, usually 26 in this case.
    :return: The greatest common divisor between a and n
    """
    if n % a == 0:
        return a
    return euclidean_algorithm(n % a, a)


def extended_euclidean_algorithm(a: int, n: int) -> int:
    """
    This method returns the multiplicative inverse of a in Z_n using the Extended Euclidean Algorithm.
    The program will only run if the greatest common divisor between a and n is 1.
    :param a: The smaller number
    :param n: The bigger number, usually 26
    :return: The multiplicative inverse of a in Z_n
    """
    if euclidean_algorithm(a, n) != 1:
        print("Unable to find the multiplicative inverse between", a, "and", n, "because the gcd is not equal to 1.")
        return
    smaller_num = a
    bigger_num = n
    quotients = [bigger_num // smaller_num]
    while bigger_num % smaller_num != 0:
        temp = smaller_num
        smaller_num = bigger_num % smaller_num
        bigger_num = temp
        quotients.append(bigger_num // smaller_num)
    k_prev_prev = 0
    k_prev = 1
    k = 0
    for q in range(0, len(quotients) - 1):
        k = k_prev_prev - k_prev * quotients[q]
        temp = k_prev
        k_prev = k
        k_prev_prev = temp
    return k % n

