"""
This project is used to code the AES encryption algorithm

Author: Timothy Wu
PID: wutp20
Date: 2/21/2022
"""
import sys
import key_expansion
import aes

# Represents the AES matrix used for the mix columns step to be used in the encryption process
aes_matrix = [[[0, 1, 0, 0, 0, 0, 0, 0], [1, 1, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0]],
              [[1, 0, 0, 0, 0, 0, 0, 0], [0, 1, 0, 0, 0, 0, 0, 0], [1, 1, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0]],
              [[1, 0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0], [0, 1, 0, 0, 0, 0, 0, 0], [1, 1, 0, 0, 0, 0, 0, 0]],
              [[1, 1, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0], [0, 1, 0, 0, 0, 0, 0, 0]]]


def add_round_key(p_text: list, key: list) -> list:
    """
    This function XOR's the 128, 192, or 256 bit block of plaintext with the same number bit block of the key
    :param p_text: The plaintext
    :param key: The key
    :return: A list of bytes
    """
    result = []
    for index in range(len(p_text)):
        result.append(aes.xor(p_text[index], key[index]))
    return result


def sub_bytes(text: str) -> str:
    """
    This function calls the substitute_bytes method from the AES field
    :param text: The text written as a string of byte data
    :return: The substituted byte string from the s-box
    """
    return key_expansion.substitute_bytes(text)


def shift_rows(message_data: list) -> list:
    """
    This function stores the 16-bit block into a matrix and shifts the rows
    :param message_data: The text written as a list of bytes
    :return: The byte matrix shifted around
    """
    matrix = [[] for i in range(4)]
    for index in range(len(message_data)):
        matrix[index % 4].append(message_data[index])
    matrix[1] = [matrix[1][1], matrix[1][2], matrix[1][3], matrix[1][0]]
    matrix[2] = [matrix[2][2], matrix[2][3], matrix[2][0], matrix[2][1]]
    matrix[3] = [matrix[3][3], matrix[3][0], matrix[3][1], matrix[3][2]]
    return matrix


def mix_columns(message_data: list) -> list:
    """
    This function multiplies the message data written as a list of bytes with the AES Matrix.
    :param message_data: The message data written as a list of bytes
    :return: The scrambled message data written as a list of bytes
    """
    result = [[0, 0, 0, 0, 0, 0, 0, 0] for i in range(4)]
    for row_index in range(len(aes_matrix)):
        for message_index in range(len(message_data)):
            result[row_index] = aes.xor(result[row_index], aes.aes_multiplication(aes_matrix[row_index][message_index],
                                                                                  message_data[message_index]))
    return result


def encryption(p_text: str, init_key: str, encryption_mode: str) -> str:
    """
    This function performs the AES encryption algorithm on the given plaintext string with the given valid initial key
    :param encryption_mode: The type of encryption mode (ECB or CBC)
    :param p_text: The plaintext string
    :param init_key: The given valid initial key
    :return: The ciphertext of the plaintext with the given initial key
    """
    encrypted_block = []
    round_number = key_expansion.round_types.get(len(init_key) // 2)
    expanded_key = key_expansion.key_expansion(init_key)
    key_expanded = key_expansion.convert_string_to_bytes(expanded_key)
    plaintext_as_bytes = key_expansion.convert_string_to_bytes(p_text)
    plaintext_index = 0
    encrypted_block_index = 0
    while plaintext_index < len(plaintext_as_bytes):
        plaintext_block = plaintext_as_bytes[plaintext_index:plaintext_index + 16]
        expanded_key_index = 0
        expanded_key_block = key_expanded[expanded_key_index:expanded_key_index + 16]

        # Add Round Key
        ciphertext_block = add_round_key(plaintext_block, expanded_key_block)
        if plaintext_index >= 16 and encryption_mode.upper() == "CBC":
            ciphertext_block = add_round_key(ciphertext_block,
                                             encrypted_block[encrypted_block_index: encrypted_block_index + 16])
            encrypted_block_index += 16
        ciphertext = key_expansion.convert_bytes_to_string(ciphertext_block)
        for j in range(round_number - 1):

            # Sub Bytes
            counter = 0
            for c in range(len(ciphertext_block)):
                ciphertext_block[c] = sub_bytes(ciphertext[counter:counter + 2])
                counter += 2
                ciphertext_block[c] = key_expansion.convert_string_to_bytes(ciphertext_block[c])

            # Shift Rows
            message_matrix = shift_rows(ciphertext_block)
            for row in range(len(message_matrix)):
                for col in range(len(message_matrix[row])):
                    message_matrix[row][col] = key_expansion.convert_bytes_to_string(list(message_matrix[row][col]))
                    message_matrix[row][col] = key_expansion.convert_string_to_bytes(''.join(message_matrix[row][col]))[
                        0]

            # Mix Columns
            ciphertext = ""
            for col in range(len(message_matrix[row])):
                column = []
                for row in range(len(message_matrix)):
                    column.append(message_matrix[row][col])
                column = mix_columns(column)
                ciphertext += key_expansion.convert_bytes_to_string(column)

            # Add Round Key
            ciphertext_block = key_expansion.convert_string_to_bytes(ciphertext)
            expanded_key_index += 16
            key_block = key_expanded[expanded_key_index:expanded_key_index + 16]
            ciphertext_block = add_round_key(ciphertext_block, key_block)
            ciphertext = key_expansion.convert_bytes_to_string(ciphertext_block)

        # Sub Bytes
        counter = 0
        for c in range(len(ciphertext_block)):
            ciphertext_block[c] = sub_bytes(ciphertext[counter:counter + 2])
            counter += 2
            ciphertext_block[c] = key_expansion.convert_string_to_bytes(ciphertext_block[c])

        # Shift Rows
        message_matrix = shift_rows(ciphertext_block)
        ciphertext_block_index = 0
        for col in range(len(message_matrix[row])):
            column = []
            for row in range(len(message_matrix)):
                column.append(message_matrix[row][col])
            for c in column:
                ciphertext_block[ciphertext_block_index] = c[0]
                ciphertext_block_index += 1

        # Add Round Key
        expanded_key_index += 16
        key_block = key_expanded[expanded_key_index:expanded_key_index + 16]
        ciphertext_block = add_round_key(ciphertext_block, key_block)
        encrypted_block.extend(ciphertext_block)
        plaintext_index += 16
    return key_expansion.convert_bytes_to_string(encrypted_block)


def main():
    """
    This function asks the user to supply a file with a hexadecimal string and a file with a valid initial key for
    the encryption process
    """
    args = sys.argv[1:]
    if len(args) == 0 or len(args) == 1 and args[0] == "--help" or args[0] == "-h":
        print("To run the program input the command: python encryption.py --plaintext=PLAINTEXT_FILE --key=INITIAL_KEY_FILE --mode=[ENCRYPTION_MODE]")
        print("Program arguments:\n\t",
              "--plaintext=PLAINTEXT_FILE is required. Provide it with the text file that contains the plaintext in hexadecimal\n\t",
              "--key=INITIAL_KEY_FILE is required in order to encrypt the message. Provide it with the text file that contains the key in hexadecimal. The key must be either 16, 24, or 32 bytes in length.\n\t",
              "--mode=[ENCRYPTION_MODE] is optional. Provide it with the encryption mode of either ECB or CBC. If not specified, the encryption mode will be ECB\n")
        print("Examples:\n\t", "python encryption.py --plaintext=aes-plaintext11.txt --key=aes-key11.txt\n\t",
              "python encryption.py --plaintext=aes-plaintext12.txt --key=aes-key12.txt --mode=CBC\n")
        print("If done correctly, your ciphertext will be printed onto the terminal.")
        return
    if len(args) not in [2, 3]:
        print("Invalid number of arguments. Please try again.")
        return
    plaintext = None
    initial_key = None
    encryption_mode = "ECB"
    for arg in args:
        arg = arg.split("=")
        flag = arg[0]
        value = arg[1]
        if flag == "--plaintext":
            plaintext_file = open(value, 'r')
            plaintext = plaintext_file.read()
            plaintext_file.close()
            needs_modification = True
            while len(plaintext) % 32 != 0:
                if len(plaintext) % 2 != 0 and needs_modification:
                    plaintext = plaintext[0:len(plaintext) - 1] + '0' + plaintext[len(plaintext) - 1]
                    needs_modification = False
                plaintext = plaintext + '0'
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
            print("Invalid flag(s). Please specify either --plaintext=PLAINTEXT_FILE, --key=INITIAL_KEY_FILE, or --mode=[ENCRYPTION_MODE]")
            return
    if plaintext is None:
        print("Please specify the plaintext using the --plaintext=PLAINTEXT_FILE")
        return
    if initial_key is None:
        print("Please specify the initial key using the --key=INITIAL_KEY_FILE")
        return
    print("The ciphertext is", encryption(plaintext, initial_key, encryption_mode))


if __name__ == '__main__':
    main()
