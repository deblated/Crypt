# VARIANT 4, Poplavskyi Stanislav, IPS-32
import random


# RABIN-KARP
def rabin_karp(text, pattern):
    n = len(text)
    m = len(pattern)
    pattern_hash = hash(pattern)
    occurrences = []

    # Slide the pattern over the text and compare hashes
    for i in range(n - m + 1):
        substring = text[i:i + m]
        substring_hash = hash(substring)

        # If hashes match, check if the substring is equal to the pattern
        if substring_hash == pattern_hash and substring == pattern:
            occurrences.append(i)

    return occurrences


# ELGAMAL
def mod_inverse(a, m):
    # Calculate the modular inverse of a modulo m using the extended Euclidean algorithm
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Inverse number does not exist")
    return x % m


def extended_gcd(a, b):
    # Calculate the greatest common divisor (gcd) of a and b using the extended Euclidean algorithm
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x


def generate_prime_number():
    # Generate a random prime number in the range of 100 to 1000
    while True:
        p = random.randint(100, 1000)
        if is_prime(p):
            return p


def is_prime(n):
    # Check if a number is prime
    if n <= 1:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_keys():
    # Generate ElGamal encryption keys
    p = generate_prime_number()
    g = random.randint(2, p - 1)
    x = random.randint(1, p - 2)
    h = pow(g, x, p)
    return p, g, h, x


def encode_text(text):
    # Encode a text string by converting each character to its ASCII value
    encoded_text = []
    for char in text:
        encoded_text.append(ord(char))
    return encoded_text


def decode_text(encoded_text):
    # Decode a list of ASCII values back to a text string
    decoded_text = ""
    for num in encoded_text:
        decoded_text += chr(num)
    return decoded_text


def encrypt(message, p, g, h):
    # Encrypt a message using the ElGamal encryption scheme
    y = random.randint(1, p - 2)    # Generate a random value y in the range (1, p-2)
    c1 = pow(g, y, p)    # Compute the first ciphertext component c1 = g^y mod p
    encoded_message = encode_text(message)    # Encode the message into a list of ASCII values
    encrypted_message = []    # Initialize the encrypted message list
    # Encrypt each ASCII value separately
    for num in encoded_message:
        c2 = (num * pow(h, y, p)) % p    # Compute the second ciphertext component c2 = (message * h^y) mod p
        encrypted_message.append((c1, c2))    # Append the ciphertext components (c1, c2) to the encrypted message
    return encrypted_message


def decrypt(message, p, x):
    # Decrypt an encrypted message using the ElGamal decryption scheme
    decrypted_message = []    # Initialize an empty list to store the decrypted message
    # Iterate over each ciphertext pair (c1, c2) in the message
    for pair in message:
        c1, c2 = pair
        inv_x = mod_inverse(pow(c1, x, p), p)    # Compute the modular inverse of c1^x mod p
        num = (c2 * inv_x) % p    # Retrieve the original ASCII value by multiplying c2 with the inverse modulo p
        decrypted_message.append(num)    # Append the decrypted ASCII value to the decrypted message
    decoded_message = decode_text(decrypted_message)    # Decode the list of ASCII values back to the original message
    return decoded_message


def rabin_karp_example():
    # Example usage of the Rabin-Karp algorithm
    print("Rabin–Karp algorithm example:")
    text = "In computer science, the Rabin–Karp algorithm or Karp–Rabin algorithm is a " \
           "string-searching algorithm created by Richard M. Karp and Michael O. Rabin"
    pattern = "Rabin"
    print("Text:", text)
    print("Pattern:", pattern)
    output = rabin_karp(text, pattern)
    if output:
        print("Pattern found at indexes:", output)
    else:
        print("Pattern not found in the text.")


def elgamal_example():
    # Example usage of the ElGamal algorithm
    print("\nElGamal encryption example:")
    p, g, h, x = generate_keys()

    message = "DeepXDE is a powerful library for solving differential equations using neural networks."

    ciphertext = encrypt(message, p, g, h)

    decrypted_message = decrypt(ciphertext, p, x)
    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message)


if __name__ == '__main__':
    rabin_karp_example()
    elgamal_example()
