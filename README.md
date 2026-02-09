# Mnemocast
This is a tool based on BIP-39, primarily for converting between mnemonic seed phrases and IPv6 addresses, decimal indices, and binary indices.

This tool only supports 12-word mnemonic phrases.
By chance I learned that a 12-word mnemonic has 2^128 entropy, which matches the number of IPv6 addresses. Therefore, by adding a salt to the mnemonic and converting it to an IPv6 address, and pointing a domain name you control to that IP, by using a salt value that only you know, you can recover your mnemonic in any network environment.

This tool supports three modes:
1. Input a mnemonic to generate the corresponding decimal index, binary index, and encrypted IPv6 address.
2. Input an encrypted IPv6 address to recover and display the mnemonic, decimal index, and binary index.
3. Input a decimal index to generate the corresponding mnemonic, binary index, and encrypted IPv6 address.

The salt (or password) can be any string.

Security:
- The tool's code is open-source and auditable; it has no network permissions.
- The tool does not generate mnemonics.
- To generate mnemonics, use https://iancoleman.io/bip39/ — preferably offline.
- Avoid copying mnemonic words when possible. In "Show entropy details" you can see the decimal number for the entropy of a 12-word phrase; copying that number is relatively safer. For maximum security, operate on an air-gapped clean PC and use this tool's mode 3 (inputting the index) to work from the number.
- The generated IPv6 will be resolved on the public Internet; ensure only you know the corresponding domain name and salt. Even if an attacker knows the IPv6 corresponds to a mnemonic, without the salt they cannot recover your mnemonic.

Disclaimer:
You are solely responsible for any losses caused by using this code.
