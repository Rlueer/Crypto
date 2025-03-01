"""
Module which contains a variety of helper functions that each
BC and AEAD construct can make use of - also code logic for input error
handling, padding, splitting blocks, and I/O to files
"""


def apply_padding(block, block_length):
    """
    Function to apply injective padding 10* to an incomplete block.
    Parameters: the block to pad, and the block length.
    Returns: the padded block.
    """

    if len(block) != block_length // 4:
        block.append(8)
    while len(block) != block_length // 4:
        block.append(0)

    return block


def list_to_string(list_to_convert):
    """
    Function to convert a list to a string.
    Parameters: the list to convert.
    Returns: the list converted into string format.
    """

    # check whether list is 2D - if so flatten to 1D
    if not list_to_convert:
        return ""

    if isinstance(list_to_convert[0], list):
        list_to_convert = sum(list_to_convert, [])

    converted_string = ""

    # for each element in the list, append it (in hex) to the string
    for i in list_to_convert:
        converted_string += (hex(i).upper()).split('X')[-1]

    return converted_string


def string_to_list(string_to_convert):
    """
    Function to convert the plaintext to a list from a string. Note the
    plaintext is made up of 16 4 bit chunks.
    Parameters: the plaintext string.
    Returns: the plaintext as a list.
    """

    converted_list = []

    # for each element in the string, cast it as an int and append to
    # the string
    for letter in string_to_convert:
        converted_list.append(int(letter, 16))

    return converted_list


def convert_to_bits(state):
    """
    Function to convert state or key to bit representation.
    Parameter: either the key or state.
    Returns: the bit representation of the parameter.
    """

    bit_state = []
    bits = []

    for i in state:
        bit_state.append((format(i, '0>4b')))

    for i in bit_state:
        for j in i:
            bits.append(int(j))

    return bits


def convert_from_bits(bit_state, noBits):
    """
    Function to convert state from bit representation 4-bit hex representation.
    Parameter: bit representation of state/key.
    Returns: the 4-bit hex representation.
    """

    # list to hold bits in groups of nibbles ready to convert into 4-bit
    # hex representation
    nibbles = []

    # list to hold the 4-bit hex representation
    hex_state = []

    # populate the nibbles list with groups of 4 bits
    for i in range(0, noBits, 4):
        nibbles.append(str(bit_state[i]) + str(bit_state[i + 1])
                       + str(bit_state[i + 2]) + str(bit_state[i + 3]))

    # convert nibbles into hex
    for i in nibbles:
        hex_state.append(int(hex(int(i, 2)), 16))

    return hex_state


def convert_to_eight_bits(state):
    """
    Function to convert state or key to bit representation.
    Parameter: either the key or state.
    Returns: the bit representation of the parameter.
    """

    bit_state = []
    bits = []

    for i in state:
        bit_state.append((format(i, '0>8b')))

    for i in bit_state:
        for j in i:
            bits.append(int(j))

    return bits


def convert_from_eight_bits(bit_state, noBits):
    """
    Function to convert state from bit representation 4-bit hex representation.
    Parameter: bit representation of state/key.
    Returns: the 4-bit hex representation.
    """

    # list to hold bits in groups of nibbles ready to convert into 4-bit
    # hex representation
    nibbles = []

    # list to hold the 4-bit hex representation
    hex_state = []

    # populate the nibbles list with groups of 4 bits
    for i in range(0, noBits, 8):
        nibbles.append(str(bit_state[i]) + str(bit_state[i + 1])
                       + str(bit_state[i + 2]) + str(bit_state[i + 3])
                       + str(bit_state[i + 4]) + str(bit_state[i + 5])
                       + str(bit_state[i + 6]) + str(bit_state[i + 7]))

    # convert nibbles into hex
    for i in nibbles:
        hex_state.append(int(hex(int(i, 2)), 16))

    return hex_state


def convert_to_bits_rev(state):
    """
    Function to convert state or key to bit representation.
    Parameter: either the key or state.
    Returns: the bit representation of the parameter.
    """

    bit_state = []
    bits = []

    # convert from hex to nibble
    for i in state:
        bit_state.append((format(i, '0>4b')[::-1]))

    # convert from nibble to individual bits
    for i in bit_state:
        for j in i:
            bits.append(int(j))

    return bits


def convert_from_bits_rev(bit_state, noBits):
    """
    Function to convert state from bit representation 4-bit hex representation.
    Parameter: bit representation of state/key.
    Returns: the 4-bit hex representation.
    """

    # list to hold bits in groups of nibbles ready to convert into
    # 4-bit hex representation
    nibbles = []

    # list to hold the 4-bit hex representation
    hex_state = []

    # populate the nibbles list with groups of 4 bits
    for i in range(0, noBits, 4):
        nibbles.append(str(bit_state[i + 3]) + str(bit_state[i + 2]) +
                       str(bit_state[i + 1]) + str(bit_state[i]))

    # convert nibbles into hex
    for i in nibbles:
        hex_state.append(int(hex(int(i, 2)), 16))

    return hex_state


def read_from_file(filename):
    """
    Function to read the inputs from a file. The flags parameter contains
    what needs to be
    read in from the file, these can include:
    p - plaintext
    k - key
    c - ciphertext
    n - nonce
    t - tag
    a - associated data
    Parameters: the name of the file and the types of data that needs to be
    read in.
    Returns: list containing all data read from the file.
    """

    variables_dictionary = {}

    with open(filename) as file:
        for line in file:
            try:
                name, value = line.split(":")
                variables_dictionary[name] = value
            except:
                print("Formatting issue found within file")

    return variables_dictionary


def write_to_file(filename, data):
    """
    Procedure to write to a file. The result of the encryption/decryption is
    to be written to the specified file
    by the user.
    Parameters: the name of the file to write and a dictionary containing
    data to write to the file.
    Returns: none.
    """

    f = open(filename, "w")
    for key in data:
        f.write(key)
        f.write(":")
        f.write(data[key])
        f.write("\n")
    f.close()
    print("Result written to " + str(filename))


def extract_inputs(variables_dictionary, flags):
    """
    Function to extract the inputs from a dictionary given the
    inputs that need to be extracted.
    Parameters: the variables in a dictionary, and the set of variables
    that need to be extracted.
    Returns: the extracted variables in a list
    """

    inputs = []
    for flag in flags:
        try:
            value = variables_dictionary[flag].strip()
            inputs.append(value)
        except KeyError:
            inputs.append("Not supplied")

    return inputs


def check_input_validity(variables_dictionary, variable_conditions):
    """
    Function to check the validity of file inputs. This function is required
    to ensure the tool is robust in handing incorrect inputs. Note, if
    multiple issues are found with the inputs, all issues are reported to the
    user.
    Parameters: the dictionary of inputs are read in from the file, and a
    dictionary of flags (i.e. what has been read in), with a boolean associated
    whether the value can be empty or not.
    Returns: boolean whether inputs are valid.
    """

    # list of valid characters in inputs
    valid_chars = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A",
                   "B", "C", "D", "E", "F", "a", "b", "c", "d", "e", "f"]
    valid = True

    # loop over each required input in the flags dictionary
    for key in variable_conditions:
        # check for the flag L
        if key == "L":
            if key not in variables_dictionary:
                # check if L is supplied
                print(str(key) + " not found in file. Please supply "
                      + str(key))
                valid = False
            else:
                try:
                    # check if L is an integer
                    int(variables_dictionary[key].strip())
                except:
                    print("Invalid value for L")
                    valid = False

            continue

        # check 1. check whether the input has been supplied
        if key not in variables_dictionary:
            print(str(key) + " not found in file. Please supply " + str(key))
            valid = False

        # check 2. check whether the input is empty
        elif variable_conditions[key][0] is False and variables_dictionary[
            key].strip("\n") == "":
            print(str(key) + " empty in file")
            valid = False

        elif len(variables_dictionary[key].strip()) < variable_conditions[key][
            1] and variable_conditions[key][2] is True:
            print(str(key) + " must be a length of " + str(
                variable_conditions[key][1]))
            valid = False
        elif len(variables_dictionary[key].strip()) < variable_conditions[key][
            1] and variable_conditions[key][2] is False:
            print(
                str(key) + " must be at least length of " + str(
                    variable_conditions[key][1]))
            valid = False
        elif len(variables_dictionary[key].strip()) > variable_conditions[key][
            1] and variable_conditions[key][2] is True:
            print(str(key) + " too long. Must be length " + str(
                variable_conditions[key][1]))
            valid = False

        # check 3. check whether all chars in the input are valid
        else:
            for char in variables_dictionary[key].strip("\n"):

                if char not in valid_chars:
                    print("Invalid character " + str(char) + " in " + str(key))
                    valid = False

    # if at least one error, report to user they need to rectify it
    if not valid:
        print("Please rectify these issues and re-run the tool")

    return valid


def xor_bits(list_one, list_two):
    """
    Function to generate a new list with the elements of a and b XOR'ed.
    Parameters: a and b, two lists to XOR
    Returns: list with pairs of elements in a and b XOR'ed
    """

    xor_list = []

    # xor each pair of elements taken from list 1 and list 2 respectively
    for i in range(0, len(list_one)):
        xor_list.append(list_one[i] ^ list_two[i])

    return xor_list


def hex_to_decimal(hex_list):
    """
    Function to convert a list of hex into decimal.
    Parameters: the hex list to convert.
    Returns: the converted list into decimal representation.
    """

    # convert each hex value to decimal
    decimal_list = []
    for i in range(0, len(hex_list), 2):
        decimal_list.append(int(hex(hex_list[i]), 16) << 4 |
                            int(hex(hex_list[i + 1]), 16))

    return decimal_list


def decimal_to_hex(decimal_list):
    """
    Function to convert decimal list to a list of hexadecimal characters.
    Parameters: The decimal list to convert.
    Returns: The converted list into hex.
    """

    hex_string_list = ""
    hex_list = []

    # convert each decimal value in list into hex
    for i in decimal_list:
        if int((hex(i)[2:]), 16) <= 15:
            hex_string_list += "0"
        hex_string_list += hex(i)[2:]

    for i in hex_string_list:
        hex_list.append(int(i, 16))

    return hex_list


def divide_into_blocks(input_message, block_length, type_of_enc):
    """
    Function to divide an input into defined size blocks.
    Parameters: the data to divide into blocks (input_message), the block
    length, and the encryption type (e) - 1 for encryption, 2 for decryption,
    3 for AEAD.
    Returns: The input message (plaintext or associated data) divided up into
    blocks.
    """

    # determine how many elements to be in each block
    characters_per_block = block_length // 4

    blocks = []
    counter = 0
    current_block = []

    # if input message is empty, return empty list
    if not input_message:
        return [[]]

    # iterate over every character in the input message and add each to
    # the current block
    for element in input_message:
        current_block.append(element)
        counter += 1

        # if size of the current block reaches the block size, add block
        # to the list of blocks and create a new block
        if counter == characters_per_block:
            blocks.append(current_block)
            counter = 0
            current_block = []

    # if the last block is full, i.e. new current block is empty, add a
    # dummy padded block to the end
    if current_block == [] and type_of_enc == 1:
        current_block = apply_padding(current_block, block_length)
        blocks.append(current_block)

    # if the last block is not full pad the rest of the block
    elif current_block != [] and type_of_enc == 2:
        current_block = apply_padding(current_block, block_length)
        blocks.append(current_block)

    # if AEAD encryption, add the current incomplete block to the list of
    # blocks
    elif current_block != [] and type_of_enc == 3:
        blocks.append(current_block)

    # if encrypting and last block is incomplete, add padding and add block
    # to the list of blocks
    elif current_block != [] and type_of_enc == 1:
        current_block = apply_padding(current_block, block_length)
        blocks.append(current_block)

    return blocks


def plaintext_length(ciphertext_length, input_length):
    """
    This method takes the user specified plaintext length, and the
    ciphertext length. It checks whether the user specified length is
    between 0 and the ciphertext length - if not, returns ciphertext length
    to reduce errors when truncating.
    Parameters: the ciphertext length, and the user input length.
    Returns: the plaintext length to use.
    """

    if 0 <= input_length <= ciphertext_length:
        return input_length
    else:
        return ciphertext_length


def increment_byte(byte):
    """
    Function to increment a byte for the counter in CTR mode.
    Parameters: input byte to increment.
    Returns: the incremented byte.
    """

    # convert the byte to decimal
    byte = hex_to_decimal(byte)[0]

    # increment the byte - if reaches 255, wrap around to 0
    if byte == 255:
        byte = 0
    else:
        byte = byte + 1

    return decimal_to_hex([byte])