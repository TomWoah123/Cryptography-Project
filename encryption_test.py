import unittest
import encryption
import key_expansion


class MyTestCase(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, True)

    def test_encryption(self):
        message_data = "3243f6a8885a308d313198a2e0370734"
        message_bytes = key_expansion.convert_string_to_bytes(message_data)
        #print(message_bytes)
        #print(len(message_bytes))
        expanded_key = key_expansion.key_expansion("2b7e151628aed2a6abf7158809cf4f3c")
        expanded_key_bytes = key_expansion.convert_string_to_bytes(expanded_key)
        #print(expanded_key_bytes)
        key_block = expanded_key_bytes[0:16]
        message_block = message_bytes[0:16]
        ciphertext_block = encryption.add_round_key(message_block, key_block)
        ciphertext = key_expansion.convert_bytes_to_string(ciphertext_block)
        #print(ciphertext)
        counter = 0
        for c in range(len(ciphertext_block)):
            ciphertext_block[c] = encryption.sub_bytes(ciphertext[counter:counter+2])
            counter += 2
            ciphertext_block[c] = key_expansion.convert_string_to_bytes(ciphertext_block[c])
        #print(ciphertext_block)
        message_matrix = encryption.shift_rows(ciphertext_block)
        for row in range(len(message_matrix)):
            for col in range(len(message_matrix[row])):
                message_matrix[row][col] = key_expansion.convert_bytes_to_string(list(message_matrix[row][col]))
                message_matrix[row][col] = key_expansion.convert_string_to_bytes(''.join(message_matrix[row][col]))[0]
        #print(message_matrix)
        ciphertext = ""
        for col in range(len(message_matrix[row])):
            column = []
            for row in range(len(message_matrix)):
                column.append(message_matrix[row][col])
            column = encryption.mix_columns(column)
            ciphertext += key_expansion.convert_bytes_to_string(column)
        ciphertext_block = key_expansion.convert_string_to_bytes(ciphertext)
        key_block = expanded_key_bytes[16:32]
        ciphertext_block = encryption.add_round_key(ciphertext_block, key_block)
        ciphertext = key_expansion.convert_bytes_to_string(ciphertext_block)
        print(ciphertext)



if __name__ == '__main__':
    unittest.main()
