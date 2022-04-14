"""
This project is used to code the key expansion in the AES field

Author: Timothy Wu
PID: wutp20
Date: 2/21/2022
"""
import aes

# This section of code reads the input from the sbox.txt file and makes a dictionary of substitution bytes.
substitutions = {}
file = open('sbox.txt', 'r')
for line in file:
    line = line.split()
    substitutions.update({line[0].lower(): line[1].lower()})

round_types = {16: 10, 24: 12, 32: 14}
round_key_number = [[1, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0, 0, 0, 0]]


def convert_string_to_bytes(
        string: str) -> list:  # string: 00112233445566778899AABBCCDDEEFF -> [[0,0,0,0,0,0,0,0],[1,0,0,0,1,0,0,0]....]
    """
    This function takes a string of valid hexadecimal numbers and converting it to a list of bytes.
    Examples:
        00 -> [0, 0, 0, 0, 0, 0, 0, 0]
        11 -> [1, 0, 0, 0, 1, 0, 0, 0]
        1C -> [0, 0, 1, 1, 1, 0, 0, 0]
    Notice how the bit values are in ascending order from the list to stay consistent with the xor function used by the
    aes.py file
    :param string: The string of valid hexadecimal numbers
    :return: A list of bytes (The bytes are a list of bits of size 8)
    """
    bytes_list = []
    for index in range(0, len(string), 2):
        byte = string[index:index + 2]
        byte = int(byte, 16)
        byte = format(byte, '#010b')[2:]
        byte = list(byte)
        byte.reverse()
        for b_index in range(len(byte)):
            byte[b_index] = int(byte[b_index])
        bytes_list.append(byte)
    return bytes_list


def convert_bytes_to_string(byte_list: list) -> str:
    """
    This function takes a list of bytes and converts it into a string of valid hexadecimal numbers
    :param byte_list: The list of bytes
    :return: The string of valid hexadecimal numbers
    """
    string = ""
    for b in byte_list:
        b = ''.join(str(byte) for byte in b)
        b = b[::-1]
        b = hex(int(b, 2))
        string = string + str(b[2:].zfill(2))
    return string


def key_expansion(initial_key: str) -> str:
    """
    This function performs the actual key expansion on the initial key
    :param initial_key: The initial key given (16-byte, 24-byte, or 32-byte)
    :return: The expanded key produced by the key expansion as a string
    """
    expansion_key = initial_key
    expansion_key_length = len(initial_key) // 2
    round_number = round_types.get(expansion_key_length)
    while len(expansion_key) < (16 * (round_number + 1)) * 2:
        for j in range(expansion_key_length // 4):
            expansion_key_as_list = convert_string_to_bytes(expansion_key)
            temp1 = expansion_key_as_list[len(expansion_key_as_list) - 4:]
            if j == 0:
                temp1 = key_expansion_core(temp1, round_key_number)
                round_key_number[0] = aes.x_time(round_key_number[0])
            if j == 4 and expansion_key_length == 32:
                for i in range(len(temp1)):
                    temp1[i] = convert_string_to_bytes("".join(list(substitute_bytes(convert_bytes_to_string([temp1[i]]))[::-1]))[::-1])[0]
            temp2 = expansion_key_as_list[len(expansion_key_as_list) - expansion_key_length:]
            temp2 = temp2[0:4]
            for b_index in range(len(temp2)):
                expansion_key = expansion_key + convert_bytes_to_string([aes.xor(temp1[b_index], temp2[b_index])])
    return expansion_key


def key_expansion_core(key: list, round_key: list) -> list:
    """
    This function makes the key expansion core used for the key expansion
    :param key: The key being passed to the key expansion core
    :param round_key: The round key being used
    :return: The modified key
    """
    key = rotate_left(key)
    key[0] = list(substitute_bytes(convert_bytes_to_string([key[0]]))[::-1])
    key[1] = list(substitute_bytes(convert_bytes_to_string([key[1]]))[::-1])
    key[2] = list(substitute_bytes(convert_bytes_to_string([key[2]]))[::-1])
    key[3] = list(substitute_bytes(convert_bytes_to_string([key[3]]))[::-1])
    for k_index in range(len(key)):
        key[k_index] = "".join(str(k) for k in key[k_index])
        key[k_index] = convert_string_to_bytes(key[k_index])
        key[k_index][0] = switch_nybbles(key[k_index][0])
        key[k_index] = key[k_index][0]
        key[k_index] = add_round_constant(key[k_index], round_key[k_index])
    return key


def rotate_left(bytes_list: list) -> list:
    """
    This function rotates the list of bytes to the left by 1
    :param bytes_list: The list of bytes
    :return: The list of bytes shifted to the left by 1
    """
    return [bytes_list[1], bytes_list[2], bytes_list[3], bytes_list[0]]


def substitute_bytes(byte: str) -> str:
    """
    This function substitutes the byte string using the substitution box values
    :param byte: The byte as a string
    :return: The substituted byte from the substitution box
    """
    return substitutions.get(byte)


def add_round_constant(byte: list, round_key: list) -> list:
    """
    This function calls the xor function from the aes.py file on the byte and the round key
    :param byte: The byte to be xor'd by the round key
    :param round_key: The round key
    :return: The xor of the byte and the round key
    """
    return aes.xor(byte, round_key)


def switch_nybbles(byte: list) -> list:
    """
    This function swaps the nybbles of the byte list to be reread back into a string from a list of bytes
    :param byte: The byte as a list of binary values
    :return: The byte list with the nybbles swapped
    """
    return byte[4:8] + byte[0:4]


def main():
    """
    This function asks the user to input a valid key and performs the AES key expansion on it
    """
    initial_key = input("Input a 16-byte, 24-byte, or 32-byte key: ")
    while len(initial_key) not in [16 * 2, 24 * 2, 32 * 2]:
        initial_key = input("The initial key you typed was not 16-bytes, 24-bytes, or 32 bytes long. Try again: ")
    print("The expanded key is", key_expansion(initial_key))

if __name__ == "__main__":
    main()

