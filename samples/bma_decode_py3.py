#!/usr/bin/env python3
# SOURCE: https://gist.github.com/zeta709/a04495a4b3235a6c6f82
# Credits to zeta709 for the python port and credits to stbuehler for the base ruby script that zeta709 based it off of.
# Python port of https://gist.github.com/stbuehler/8616943

# Disclaimer
# There is absolutely no guarantee.
#
# Guide
# 0. Install Android SDK and Android Backup Extractor
# 1. Backup Battle.net Authenticator
#    adb backup com.blizard.bma -f bma.ab
# 2. Extract files
#    java -jar abe.jar unpack bma.ab bma.tar
#    tar -xf bma.tar
# 3. Open a file named "com.blizzard.bma.AUTH_STORE.xml"
# 4. Get the value of "com.blizzard.bma.AUTH_STORE.HASH"
# 5. Use this tool to get the secret key
# 6. (Optional) Use any QR code generator
#    (Offline QR code generators are recommended)
# 7. Use RFC6238-compliant TOTP application with the result
#    (algorithm=SHA1, digits=8, period=30)

import sys
import base64

def bma_decode(bma_code, account_name):
    # Since the original ruby code does not specify where the mask come from,
    # some research(?) has been executed.
    # The mask in hex string can be found in the following post:
    # Quote: http://forum.xda-developers.com/showpost.php?p=7303107&postcount=94
    # > "398e27fc50276a656065b0e525f4c06c04c61075286b8e7aeda59da98"
    # > "13b5dd6c80d2fb38068773fa59ba47c17ca6c6479015c1d5b8b8f6b9a"
    # Let this hex string be mask_hex and get the mask with the following code:
    # mask = [ord(x) for x in mask_hex.decode("hex")]
    mask = [57,142,39,252,80,39,106,101,
            96,101,176,229,37,244,192,108,
            4,198,16,117,40,107,142,122,
            237,165,157,169,129,59,93,214,
            200,13,47,179,128,104,119,63,
            165,155,164,124,23,202,108,100,
            121,1,92,29,91,139,143,107,
            154]

    # Java Equivalent - String#getBytes(StandardCharsets.UTF_8)
    strBytes = bytes(bma_code, "utf-8")

    # Java Equivalent - Character#digit(byte, 16)
    x = base64.b16decode(strBytes, True)
    #print("x (base16 decoded string chars): ")
    #print(x)
    #print()

    #for x, y in zip(x, mask):
    #    print(x)
    #    print(y)
    #    print()

    # The for loop is inverted, the for loop gives values to chr... for some reason
    y = "".join(chr(x ^ y) for x, y in zip(x, mask))

    #print("y: ")
    #print(y)

    secret_hex = bytes(y[0:40], "utf-8")
    secret = base64.b32encode(base64.b16decode(secret_hex, True))
    serial = y[40:]
    secret_hex = secret_hex.decode("utf-8")
    secret = secret.decode("utf-8")

    print("secret (hex):", secret_hex)
    print("secret:", secret)
    print("serial:", serial)

    print("otpauth://totp/Battle.net:{}?secret={}&issuer=Battle.net&digits=8".
          format(account_name, secret))

def main():
    print("Enter bma_code: ")
    bma_code = sys.stdin.readline().strip()
    print("Enter account name: ")
    account_name = sys.stdin.readline().strip()
    bma_decode(bma_code, account_name)

if __name__ == "__main__":
    main()
