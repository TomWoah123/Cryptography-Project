"""
This project is used to code the addition and multiplication function of polynomials in Z_2

Author: Timothy Wu
PID: wutp20
Date: 2/21/2022
"""


def addition(list_one: list, list_two: list) -> list:
    """
    This method returns the sums of two lists which represent the coefficients of a polynomial in Z_2
    :param list_one: The first list of polynomial coefficients
    :param list_two: The second list of polynomial coefficients
    :return: A list of the coefficient sums of the two polynomials
    """
    sums = []
    for index in range(len(list_one)):
        sums.append((list_one[index] + list_two[index]) % 2)
    return sums


def multiplication(list_one: list, list_two: list) -> list:
    """
    This method returns the product of two lists which represent the coefficients of a polynomial in Z_2
    :param list_one: The first list of polynomial coefficients
    :param list_two: The second list of polynomial coefficients
    :return: A list of the coefficient products of the two polynomials
    """
    products = [0 for i in range(len(list_one) + len(list_two))]
    for index_one in range(len(list_one)):
        for index_two in range(len(list_two)):
            products[index_one + index_two] += (list_one[index_one] * list_two[index_two]) % 2
    return products
