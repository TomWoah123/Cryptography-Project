"""
This project is used to code the addition and multiplication function of polynomials in Z_2 inside the AES field

Author: Timothy Wu
PID: wutp20
Date: 2/21/2022
"""

# The AES_polynomial is x^8 + x^4 + x^3 + x + 1
AES_polynomial = [1, 1, 0, 1, 1, 0, 0, 0, 1]


def xor(list_one: list, list_two: list) -> list:
    """
    This function performs addition in Z_2 which is the equivalent of bitwise XOR on two binary lists
    :param list_one: The first polynomial written as a list
    :param list_two: The second polynomial written as a list
    :return: The sum of the two polynomials
    """
    sum_of_lists = []
    for index in range(min(len(list_one), len(list_two))):
        sum_of_lists.append((list_one[index] + list_two[index]) % 2)
    return sum_of_lists


def aes_multiplication(list_one: list, list_two: list) -> list:
    """
    This function performs AES multiplication between two polynomials
    :param list_one: The first polynomial written as a list
    :param list_two: The second polynomial written as a list
    :return: The product of the two polynomials under the AES field
    """
    products = [0 for i in range(len(list_one))]
    terms = []
    a = list_one
    for coefficient in list_two:
        if coefficient == 1:
            terms.append(a)
        else:
            terms.append([0 for i in range(len(a))])
        a = x_time(a)

    for term_index in range(len(terms)):
        for product_index in range(len(products)):
            products[product_index] = (products[product_index] + terms[term_index][product_index]) % 2
    return products[0:8]


def x_time(list_one: list) -> list:
    """
    This function multiplies the polynomial by x [0, 1]
    :param list_one: The polynomial written as a list
    :return: The polynomial shifted to the left ("right" in this case) and XOR'd with the AES polynomial if necessary
    """
    left_shifted = left_shift(list_one)
    if left_shifted[-1] == 1:
        left_shifted = xor(left_shifted, AES_polynomial)
    return left_shifted[0:8]


def left_shift(list_one: list) -> list:
    """
    This function shifts the polynomial to the left ("right" in this case because the higher order is at the end of the
    list)
    :param list_one: The polynomial written as a list
    :return: The polynomial shifted
    """
    list_shifted = [0] + list_one
    return list_shifted[0:9]


# polynomial_one = [1, 1, 1, 0, 0, 0, 1, 1]
# polynomial_two = [1, 1, 0, 1, 1, 0, 1, 1]



