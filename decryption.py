"""
This project is used to code the AES decryption algorithm

Author: Timothy Wu
PID: wutp20
Date: 2/21/2022
"""

import key_expansion
import aes
import encryption
import sys

# This section of code reads the input from the sbox.txt file and makes a reverse dictionary of substitution bytes.
inverse_substitutions = {}
file = open('sbox.txt', 'r')
for line in file:
    line = line.split()
    inverse_substitutions.update({line[1].lower(): line[0].lower()})

# Represents the inverse of the AES matrix to be used in the decryption process
inverse_aes_matrix = [
    [[0, 1, 1, 1, 0, 0, 0, 0], [1, 1, 0, 1, 0, 0, 0, 0], [1, 0, 1, 1, 0, 0, 0, 0], [1, 0, 0, 1, 0, 0, 0, 0]],
    [[1, 0, 0, 1, 0, 0, 0, 0], [0, 1, 1, 1, 0, 0, 0, 0], [1, 1, 0, 1, 0, 0, 0, 0], [1, 0, 1, 1, 0, 0, 0, 0]],
    [[1, 0, 1, 1, 0, 0, 0, 0], [1, 0, 0, 1, 0, 0, 0, 0], [0, 1, 1, 1, 0, 0, 0, 0], [1, 1, 0, 1, 0, 0, 0, 0]],
    [[1, 1, 0, 1, 0, 0, 0, 0], [1, 0, 1, 1, 0, 0, 0, 0], [1, 0, 0, 1, 0, 0, 0, 0], [0, 1, 1, 1, 0, 0, 0, 0]]]


def inverse_sub_bytes(text: str) -> str:
    """
    This function returns the inverse substitution of the text
    :param text: The text written as a string of byte data
    :return: The substituted byte from the inverse substitution box
    """
    return inverse_substitutions.get(text)


def inverse_shift_rows(message_data: list) -> list:
    """
    This function stores the 16-bit block into a matrix and shifts the rows back into their order
    :param message_data: The text written as a list of bytes
    :return: The byte matrix shifted back into order
    """
    matrix = [[] for i in range(4)]
    for index in range(len(message_data)):
        matrix[index % 4].append(message_data[index])
    matrix[1] = [matrix[1][3], matrix[1][0], matrix[1][1], matrix[1][2]]
    matrix[2] = [matrix[2][2], matrix[2][3], matrix[2][0], matrix[2][1]]
    matrix[3] = [matrix[3][1], matrix[3][2], matrix[3][3], matrix[3][0]]
    return matrix


def inverse_mix_columns(message_data: list) -> list:
    """
    This function multiplies the message data written as a list of bytes with the inverse AES Matrix.
    :param message_data: The scrambled message data written as a list of bytes
    :return: The unscrambled message data written as a list of bytes
    """
    result = [[0, 0, 0, 0, 0, 0, 0, 0] for i in range(4)]
    for row_index in range(len(inverse_aes_matrix)):
        for message_index in range(len(message_data)):
            result[row_index] = aes.xor(result[row_index],
                                        aes.aes_multiplication(inverse_aes_matrix[row_index][message_index],
                                                               message_data[message_index]))
    return result


def decryption(c_text: str, init_key: str, decryption_mode: str) -> str:
    """
    This function performs the AES Decryption algorithm on the given ciphertext string with the given valid initial key
    :param c_text: The cipher text
    :param init_key: The given valid initial key
    :param decryption_mode: The type of decryption mode (ECB or CBC)
    :return: The plaintext of the ciphertext with the given key
    """
    decrypted_block = []
    round_number = key_expansion.round_types.get(len(init_key) // 2)
    expanded_key = key_expansion.key_expansion(init_key)
    expanded_key_bytes = key_expansion.convert_string_to_bytes(expanded_key)
    ciphertext_as_bytes = key_expansion.convert_string_to_bytes(c_text)
    ciphertext_index = 0
    decrypted_block_index = 0
    while ciphertext_index < len(ciphertext_as_bytes):
        key_block_index = len(expanded_key_bytes) - (len(init_key) // 2)

        # Add Round Key
        key_block = expanded_key_bytes[key_block_index:key_block_index + 16]
        key_block_index -= 16
        ciphertext_block = ciphertext_as_bytes[ciphertext_index:ciphertext_index + 16]
        plaintext_block = encryption.add_round_key(ciphertext_block, key_block)

        for i in range(round_number - 1):

            # Inverse Shift Rows
            message_matrix = inverse_shift_rows(plaintext_block)
            for row in range(len(message_matrix)):
                for col in range(len(message_matrix[row])):
                    message_matrix[row][col] = key_expansion.convert_bytes_to_string([list(message_matrix[row][col])])
                    message_matrix[row][col] = key_expansion.convert_string_to_bytes(''.join(message_matrix[row][col]))[
                        0]
            plaintext = ""
            for col in range(len(message_matrix[row])):
                column = []
                for row in range(len(message_matrix)):
                    column.append(message_matrix[row][col])
                plaintext += key_expansion.convert_bytes_to_string(column)
            plaintext_block = key_expansion.convert_string_to_bytes(plaintext)

            # Inverse Sub Bytes
            counter = 0
            for c in range(len(plaintext_block)):
                plaintext_block[c] = inverse_sub_bytes(plaintext[counter: counter + 2])
                counter += 2
                plaintext_block[c] = key_expansion.convert_string_to_bytes(plaintext_block[c])[0]

            # Add Round Key
            key_block = expanded_key_bytes[key_block_index:key_block_index + 16]
            key_block_index -= 16
            plaintext_block = encryption.add_round_key(plaintext_block, key_block)

            # Inverse Mix Columns
            message_matrix = [[] for i in range(4)]
            for index in range(len(plaintext_block)):
                message_matrix[index % 4].append(plaintext_block[index])
            plaintext = ""
            for col in range(len(message_matrix[row])):
                column = []
                for row in range(len(message_matrix)):
                    column.append(message_matrix[row][col])
                column = inverse_mix_columns(column)
                plaintext += key_expansion.convert_bytes_to_string(column)
            plaintext_block = key_expansion.convert_string_to_bytes(plaintext)

        # Inverse Shift Rows
        message_matrix = inverse_shift_rows(plaintext_block)
        for row in range(len(message_matrix)):
            for col in range(len(message_matrix[row])):
                message_matrix[row][col] = key_expansion.convert_bytes_to_string([list(message_matrix[row][col])])
                message_matrix[row][col] = key_expansion.convert_string_to_bytes(''.join(message_matrix[row][col]))[0]
        plaintext = ""
        for col in range(len(message_matrix[row])):
            column = []
            for row in range(len(message_matrix)):
                column.append(message_matrix[row][col])
            plaintext += key_expansion.convert_bytes_to_string(column)
        plaintext_block = key_expansion.convert_string_to_bytes(plaintext)

        # Inverse Sub Bytes
        counter = 0
        for c in range(len(plaintext_block)):
            plaintext_block[c] = inverse_sub_bytes(plaintext[counter: counter + 2])
            counter += 2
            plaintext_block[c] = key_expansion.convert_string_to_bytes(plaintext_block[c])[0]

        # Add Round Key
        key_block = expanded_key_bytes[key_block_index:key_block_index + 16]
        key_block_index -= 16
        plaintext_block = encryption.add_round_key(plaintext_block, key_block)
        if ciphertext_index >= 16 and decryption_mode == "CBC":
            plaintext_block = encryption.add_round_key(plaintext_block,
                                                       ciphertext_as_bytes[ciphertext_index - 16: ciphertext_index])
            decrypted_block_index += 16

        decrypted_block.extend(list(plaintext_block))
        ciphertext_index += 16
    return key_expansion.convert_bytes_to_string(decrypted_block)


def main():
    """
    This function asks the user to supply a file with a hexadecimal string and a file with a valid initial
    key for the decryption process
    """
    args = sys.argv[1:]
    if len(args) == 0 or len(args) == 1 and args[0] == "--help" or args[0] == "-h":
        print("To run the program input the command: python decryption.py --ciphertext=CIPHERTEXT_FILE --key=INITIAL_KEY_FILE --mode=[DECRYPTION_MODE]")
        print("Program arguments:\n\t",
              "--ciphertext=CIPHERTEXT_FILE is required. Provide it with the text file that contains the ciphertext in hexadecimal\n\t",
              "--key=INITIAL_KEY_FILE is required in order to decrypt the message. Provide it with the text file that contains the key in hexadecimal. The key must be either 16, 24, or 32 bytes in length.\n\t",
              "--mode=[DECRYPTION_MODE] is optional. Provide it with the decryption mode of either ECB or CBC. If not specified, the decryption mode will be ECB\n")
        print("Examples:\n\t",
              "python decryption.py --ciphertext=aes-ciphertext10.txt --key=aes-key10.txt\n\t",
              "python decryption.py --ciphertext=aes-ciphertext10.txt --key=aes-key10.txt --mode=CBC\n")
        print("If done correctly, your plaintext will be printed onto the terminal.")
        return
    if len(args) not in [2, 3]:
        print("Invalid number of arguments. Please try again.")
        return
    ciphertext = None
    initial_key = None
    encryption_mode = "ECB"
    for arg in args:
        arg = arg.split("=")
        flag = arg[0]
        value = arg[1]
        if flag == "--ciphertext":
            ciphertext_file = open(value, 'r')
            ciphertext = ciphertext_file.read()
            ciphertext_file.close()
        elif flag == "--key":
            initial_key_file = open(value, 'r')
            initial_key = initial_key_file.read()
            initial_key_file.close()
            if len(initial_key) not in [16 * 2, 24 * 2, 32 * 2]:
                print("Invalid initial key length. The initial key should be either 16, 24, or 32 bytes")
                return
        elif flag == "--mode":
            encryption_mode = value
            if encryption_mode.upper() not in ['ECB', 'CBC']:
                print("Invalid encryption mode. Please specify either ECB or CBC.")
                return
        else:
            print("Invalid flag(s). Please specify either --ciphertext=CIPHERTEXT_FILE, --key=INITIAL_KEY_FILE, or --mode=[DECRYPTION_MODE]")
            return
    if ciphertext is None:
        print("Please specify the ciphertext using the --ciphertext=CIPHERTEXT_FILE")
        return
    if initial_key is None:
        print("Please specify the initial key using the --key=INITIAL_KEY_FILE")
        return
    print("The plaintext is:", decryption(ciphertext, initial_key, encryption_mode))


if __name__ == '__main__':
    main()
