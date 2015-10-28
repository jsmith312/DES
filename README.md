# DES Encryption
Computer Security project for CSC466 Fall 2015

	java DES -h

This should list out all the command line options supported by your program.

	java DES -k

This should generate a DES key, encoded in hex, printed on the command line.

Each time this mode is executed, a different key must be generated, i.e., you must extract some
entropy from the environment.

You should not generate a weak key.

	java DES -e <64 bit key in hex> -i <input_file> -o <output_file>

This should encrypt the file <input file> using <64 bit key in hex> and store the encrypted
file in <output file>.

Each encrypted block should be printed as 16 ascii hex characters, separated by newlines. The
last block should be padded appropriately.

There is no restriction on the size of the input file.

Use CBC mode. Use a cryprographically secure random number generator to create the initialization
vector (IV). Prepend this IV to the output (in cleartext).

	java DES -d <64 bit key in hex> -i <input file> -o <output file>
This should decrypt the file <input file> using <64 bit key in hex> and store the plain text
file in <output file>.

