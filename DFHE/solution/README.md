# Solution
The given program ensures that KEY_1 lies in range(1000,2000) and KEY_2 lies in range(6000,7000). So we can brute force try all the possible values of KEY_1 and KEY_2 (which isn't much, nearly a million). Also, we can make some optimizations to reduce the program runtime. In the following segment:

def messed_up(x, y):
    enc_1 = (primitive ** y) % modulus
    enc_2 = (enc_1 ** x) % modulus
    return enc_2
mess = messed_up(KEY_1, KEY_2)

The function messed_up can be simplified to use the built in modular exponentiation in python, i.e., 

mess = pow(primitive, x*y, modulus)
string = bin(mess)[2:] # convert mess to binary

Instead of trying to make the length of string equal to the length of xor_1 by repeating the same string, we can instead just access string[i % len(string)] for any i. Using the given output, we know the value of ct. Since the inverse of xor is also xor, we can recover the value of variable xor_1 by running the last for loop, but interchanging the position of xor_1 and ct.

xor_1 = ""
for i in range(len(ct)):
            xor_1 += str(int(ct[i]) ^ int(string[i % len(string)]))

Once we have xor_1, we can convert it to an integer and then to a hex value, let's call it hex_flag.

int_flag = int(xor_1, 2)
hex_flag = hex(int_flag)[2:]

Finally, we know that the flag starts with "CSeC{", so our hex_flag must start with "435365437b", and when this is found, we unhexlify and decode and print the flag. The decoding program takes nearly 55 seconds to find the flag.
The decode program written by me can be found here: https://text.is/828O
