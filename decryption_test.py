import unittest
import decryption
import key_expansion
import encryption


class MyTestCase(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, True)

    def test_decryption(self):
        message_data = "dda97ca4864cdfe06eaf70a0ec0d7191"
        message_bytes = key_expansion.convert_string_to_bytes(message_data)
        expanded_key = key_expansion.key_expansion("000102030405060708090a0b0c0d0e0f1011121314151617")
        expanded_key_bytes = key_expansion.convert_string_to_bytes(expanded_key)
        key_block_index = len(expanded_key_bytes) - 24

        # Add Round Key
        key_block = expanded_key_bytes[key_block_index:key_block_index + 16]
        key_block_index -= 16
        print(key_expansion.convert_bytes_to_string(key_block))
        print()
        message_block = message_bytes[0:16]
        plaintext_block = encryption.add_round_key(message_block, key_block)
        plaintext = key_expansion.convert_bytes_to_string(plaintext_block)
        print(plaintext)

        # Inverse Shift Rows
        message_matrix = decryption.inverse_shift_rows(plaintext_block)
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
            plaintext_block[c] = decryption.inverse_sub_bytes(plaintext[counter: counter + 2])
            counter += 2
            plaintext_block[c] = key_expansion.convert_string_to_bytes(plaintext_block[c])[0]
        plaintext = key_expansion.convert_bytes_to_string(plaintext_block)
        print(plaintext)

        # Add Round Key
        key_block = expanded_key_bytes[key_block_index:key_block_index + 16]
        print(key_expansion.convert_bytes_to_string(key_block))
        print()
        key_block_index -= 16
        plaintext_block = encryption.add_round_key(plaintext_block, key_block)
        plaintext = key_expansion.convert_bytes_to_string(plaintext_block)
        print(plaintext)

        # Inverse Mix Columns
        message_matrix = [[] for i in range(4)]
        for index in range(len(plaintext_block)):
            message_matrix[index % 4].append(plaintext_block[index])
        plaintext = ""
        for col in range(len(message_matrix[row])):
            column = []
            for row in range(len(message_matrix)):
                column.append(message_matrix[row][col])
            column = decryption.inverse_mix_columns(column)
            plaintext += key_expansion.convert_bytes_to_string(column)
        print(plaintext)
        plaintext_block = key_expansion.convert_string_to_bytes(plaintext)

        # Inverse Shift Rows
        message_matrix = decryption.inverse_shift_rows(plaintext_block)
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
            plaintext_block[c] = decryption.inverse_sub_bytes(plaintext[counter: counter + 2])
            counter += 2
            plaintext_block[c] = key_expansion.convert_string_to_bytes(plaintext_block[c])[0]
        plaintext = key_expansion.convert_bytes_to_string(plaintext_block)
        print(plaintext)

        # Add Round Key
        key_block = expanded_key_bytes[key_block_index:key_block_index + 16]
        key_block_index -= 16
        plaintext_block = encryption.add_round_key(plaintext_block, key_block)
        plaintext = key_expansion.convert_bytes_to_string(plaintext_block)
        print(plaintext)



if __name__ == '__main__':
    unittest.main()
