from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from itertools import permutations
import os
import codecs


# python3 memcrypt_analysis.py

# Below are header values for common file types.
JPEG_HDR = b'\xFF\xD8\xFF\xE0'
MS_OFFICE_HDR = b'\x50\x4B\x03\x04\x14\x00\x06\x00'
PNG_HDR = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
PDF_HDR = b'%PDF-'


def isIncremental(buffer):
    """TODO 1: Please implement a function which will:

        1) Check if the 16-byte buffer contains incremental values (at 1-step intervals).
        2) Return True if incremental values are detected. Otherwise, the function should return False.

     Examples of the many incremental values, found in memory_dump.bin, include:

     40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F (ASCII: @ABCDEFGHIJKLMNO)
     58 59 5A 5B 5C 5D 5E 5F 60 61 62 63 64 65 66 67 (ASCII: XYZ[\]^_`abcdefg)
     6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 (ASCII: jklmnopqrstuvwxy)

     Keyword arguments:
     buffer -- the buffer to check for incremental values. 16-byte size buffers are passed in by default.
    """
    hex_buffer = codecs.encode(buffer, 'hex') # Encode ASCII to hex
    hex_string = hex_buffer.decode('utf-8') # Transform into string literal

    int_array = []
    list_of_indexes = list(range(0, 31, 2)) # Create list of 16 index values: 0,2,4,6....30

    for i in list_of_indexes: # Extract values as 2 character strings, covert them to integers and append to a list
        value = hex_string[i:i+2]
        int_array.append(int(value, 16))

    if int_array == list(range(int_array[0], int_array[0]+16, 1)): # Detectd if the list of integers matches a list of incremental values where both start with the same value 
        return True

    return False


def decryptFile(candidates):
    """TODO 2: Please implement a function which will:

        1) Generate all permutations of candidate values (this has been done for you in the code below)
        2) Test each candidate value against 'data\encrypted_file' using the Cryptodome.Cipher.AES decrypt* function. Ensure mode AES.MODE_CBC is used.
        3) Check the header of each decryption attempt to determine if decryption was successful. The isKnownHeader() function can be used for this purpose.
        4) Output the correct key and IV (via a standard print statement) on successful decryption.
        5) Write the decrypted file to the 'data' directory.
        6) Consider extending the code to append the correct extension based on isKnownHeader() function match. (e.g. if the function determines the decrypted file to be JPG, add the .jpg extension).

     *See https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html for example usage.

     Keyword arguments:
     candidates -- The candidate keys and initialisation vectors (IVs) one wishes to test.
    """
    permu = list(permutations(candidates, 2))  # This function may be used to generate all permutations of candidate values.


    file_in = open('data/encrypted_file', 'rb')
    encrypted_data = file_in.read()  # Open the encrypted file and assign its content to a variable
    file_in.close()
    decrypted_data = ''

    for combination in permu:  # For every combination of key and iv...
        key = combination[0]
        iv = combination[1]
        file_extension = []

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)  # ...use the current value of key and iv to decrypt ciphered data...

        if isKnownHeader(decrypted_data, file_extension):  #  ...and verify if decrypted file has a known header. If it does...
          print(key, iv)  # Display correct combination of key and iv in terminal, and...

          output_file = open('data/decrypted_file' + file_extension[0], 'xb')
          output_file.write(decrypted_data) #...save the decrypted data as a new file with correct extension




def isKnownHeader(buffer, file_extension):
    """This function performs analysis on the decrypted buffer to determine if it matches a known header (i.e. file type).
     If a match is detected, then it is likely the decryption process was successful.

     Keyword arguments: 
     buffer -- The buffer we wish to determine if decryption was successful.
    """
    if JPEG_HDR in buffer[0:len(JPEG_HDR)]:
        file_extension.append('.jpeg')
        return True
    if MS_OFFICE_HDR in buffer[0:len(MS_OFFICE_HDR)]:
        file_extension.append('.docb')
        return True
    if PNG_HDR in buffer[0:len(PNG_HDR)]:
        file_extension.append('.png')
        return True
    if PDF_HDR in buffer[0:len(PDF_HDR)]:
        file_extension.append('.pdf')
        return True
    return False


def memoryAnalysis(file, offset):
    """This function iterates through the memory_dump.bin file and reads the content (buffer) of the file at 16-byte offsets.
     The 16-byte buffer will be checked by the isIncremental() function to determine if the data is a candidate cryptographic value or benign.
     If isIncremental() returns false, the 16-byte buffer is considered a candidate value and will be added to the candidates list.

     Keyword arguments: 
     file -- the memory dump file we wish to perform analysis on.
     offset -- the offset value to operate against the memory dump file. Fixed at 16 bytes for this task.
    """
    candidates = []
    filesize = os.path.getsize(file)

    with open(file, "rb") as fh:
        for i in range(0, filesize, offset):
            read = fh.read(offset)

            if isIncremental(read) == False:
                candidates.append(read)
                #print(read)

    return candidates


def main():
    # We begin by analysing the memory dump file. A list of candidate values will be returned by the function.
    my_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.join(my_path, "data/memory_dump.bin")

    candidates = memoryAnalysis(path, 16)
    # candidates = memoryAnalysis(r"data\memory_dump.bin", 16)

    # We then attempt to decrypt the encypted_file by trying all possible permutation of candidate values.
    decryptFile(candidates)


if __name__ == "__main__":
    main()
