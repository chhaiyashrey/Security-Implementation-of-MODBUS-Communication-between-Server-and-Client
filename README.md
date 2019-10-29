# Security-Implementation-of-MODBUS-Communication-between-Server-and-Client
-Authentication (RSA), data Integrity (HASH) and Encryption (AES- Diffie-Hellman Session Key) implementation in Linux terminal with python language.  
-IPSEC VPN and FIREWALL implementation.

As we all know that Modbus communication only transfers binary data. so, implementing security in 502 port is little difficult. 
so instead of 502 port we can use any other port to transfer diffie-hellman session key. and after creating Shared secret key,
we can shift to the 502 port for further communication.

so hashing, diffie-hellman session key and RSA certificate/signature these 3 important securities has implemented in the given code.



To understand further about every chunk of code please refer report.pdf 
it also includes IPsec VPN and Firewall to make system more secure.
