#!/usr/bin/env python3

# made by : H4Z3

# main(), argparse, input file support and bug fixes added after

# https://pypi.org/project/twofish/

import argparse
import sys

# COMPATIBILITY FIX FOR TWOFISH: the twofish library (https://pypi.org/project/twofish/)
# does `import imp` internally, 'imp' was removed in python appereantly
# so on newer Python the library crashes the moment it is imported
# on Python 3.12 or newer, we make a tiny stand-in for `imp` with the one
# function the library needs (find_module), which just finds a file's location.
# On older Python, the real `imp` exists, so we leave everything alone.
if sys.version_info >= (3, 12):
    import importlib.util
    import types

    _imp = types.ModuleType('imp')

    def _find_module(name):
        spec = importlib.util.find_spec(name)
        return (None, spec.origin, None)  # the library only uses [1], the path

    _imp.find_module = _find_module
    sys.modules['imp'] = _imp

from twofish import Twofish

#for some reason 'key' does not work at all so use 'py main.py' for windows and python3 for unix systems

help_menu = """
USAGE:
  py main.py twofish [FLAGS] [OPTIONS] 

FLAGS:
  -d, --decode   Decrypt input text or file
  -e, --encode   Encrypt input text or file
  -h, --help     Show this menu

OPTIONS:
  -i, --inputFile <input file>   Input file to encrypt or decrypt
  -k, --key <key>                Encryption key (1-32 bytes)
  -o, --output <output file>     Output file for encrypted or decrypted text
  -t, --text <text>              Input text to encrypt or decrypt (16 bytes)

EXAMPLES:
  twofish -e -t YELLOWSUBMARINES -k mySecretKey
  twofish -d -t 27570f92486cff1b8bf056671533864b -k mySecretKey
"""


def encode(args):
    text = args.text
    key = args.key

    # check for valid input
    if text and key:
        # FIX: I decided to use utf-8 and to measure key bytes too
        text_bytes = text.encode('utf-8')
        key_bytes = key.encode('utf-8')

        # check for valid block & key length
        if len(text_bytes) == 16 and len(key_bytes) <= 32:
            secret = Twofish(key_bytes)
            rawciphertext = secret.encrypt(text_bytes)
            ciphertext = rawciphertext.hex()

            output = f"Encrypting | {text}\nKey | {key}\nRaw Ciphertext | {rawciphertext}\nCiphertext | {ciphertext}"

            # check for output file
            return [ciphertext, True] if args.output else [output, True]
        else:
            if len(text_bytes) != 16:
                return [f'Error: Invalid Block Length {text}, must be 16 bytes', False]

            elif len(key_bytes) > 32:
                return [
                    f'Error: Invalid key Length {key}, must be 1 to 32 bytes long',
                    False,
                ]

            else:
                return ['Error: Make sure to have a 16 byte block and a key', False]

    elif text is None and key is None:
        return ['Error: No text or key supplied', False]

    elif text is None:
        return ['Error: No text supplied', False]

    elif key is None:
        return ['Error: No key supplied', False]

    else:
        return ['Error: Make sure to use a 16 byte string and a key', False]


def decode(args):
    ciphertext = args.text
    key = args.key

    if ciphertext and key:
        return decryption(key, ciphertext, args)
    if ciphertext is None and key is None:
        return ['Error: No text or key supplied', False]

    elif ciphertext is None:
        return ['Error: No text supplied', False]

    elif key is None:
        return ['Error: No key supplied', False]

    else:
        return ['Error: Make sure to use a 16 byte string and a key', False]


def decryption(key, ciphertext, args):
    key_bytes = key.encode('utf-8')

    if len(key_bytes) > 32:
        return [
            f'Error: Invalid key Length {key}, must be 1 to 32 bytes long',
            False,
        ]

    # FIX: this used to sit outside any error check, so typing something
    # that isn't hex crashed the whole program
    try:
        rawciphertext = bytes.fromhex(ciphertext)
    except ValueError:
        return ['Error: Ciphertext must be hex (only 0-9 and a-f)', False]

    if len(rawciphertext) != 16:
        return ['Error: Ciphertext must be 32 hex characters (16 bytes)', False]

    secret = Twofish(key_bytes)
    rawplaintext = secret.decrypt(rawciphertext)

    # decode attempt: turn the bytes into readable text if possible
    try:
        plaintext = rawplaintext.decode('utf-8')
    except UnicodeDecodeError:
        # usually means the wrong key was used, so we keep the raw bytes
        plaintext = rawplaintext

    output = f"Decrypting | {ciphertext}\nRaw Ciphertext | {rawciphertext}\nKey | {key}\nPlaintext | {plaintext}"

    return [plaintext, True] if args.output else [output, True]


def main():
    # argparse reads what was typed in the terminal and builds `args`
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-e', '--encode', action='store_true')
    parser.add_argument('-d', '--decode', action='store_true')
    parser.add_argument('-h', '--help', action='store_true')
    parser.add_argument('-i', '--inputFile')
    parser.add_argument('-k', '--key')
    parser.add_argument('-o', '--output')
    parser.add_argument('-t', '--text')
    args = parser.parse_args()

    # show the help menu if asked, or if you didn't pick exactly one of -e / -d
    if args.help or args.encode == args.decode:
        print(help_menu)
        return

    # if an input file was given, its contents become the text
    if args.inputFile:
        try:
            with open(args.inputFile, 'r', encoding='utf-8') as f:
                args.text = f.read().strip()
        except OSError as error:
            print(f'Error: could not read {args.inputFile} ({error})')
            return

    # run the right function. Each one returns [message, did_it_work]
    if args.encode:
        result, success = encode(args)
    else:
        result, success = decode(args)

    # save to a file if it worked and one was asked for, otherwise print
    if success and args.output:
        # raw bytes (from a failed text decode) need binary mode
        mode = 'wb' if isinstance(result, bytes) else 'w'
        with open(args.output, mode) as f:
            f.write(result)
        print(f'Saved to {args.output}')
    else:
        print(result)


if __name__ == '__main__':
    main()