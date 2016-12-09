# ChatServer Created by Dominik Zduńczyk, Karol Niewiadomski, Piotr Kopczuk

THIS IS SERVER GIT REPO

The main objective of this work is to implement a system that allows to exchange cryptographic secrets between two 
entities in a reliable and secure way. The idea is that the system integrates and makes available a series of distribution 
schemes and protocols according to cryptographic keys, as well as ways to generate them from passwords. In principle, 
the system must be able to be implemented in a single application that, after running on two different computers or devices, 
allows the generation and exchange of secrets between both instances.

Among others to think about, the system should provide the following basic functionalities:
#1. Generation of a cryptographic secret from passwords entered by the user, namely through algorithms such as Password Based Key Derivation Function 2 (PBKDF2);
#2. Exchange a cryptographic secret using the DiffieHellman key agreement protocol;
#3. Exchange a cryptographic secret using Merkle Puzzles;
#4. Exchange a cryptographic secret using Rivest Shamir Adleman (RSA);
#5. Distribution of new cipher keys from pre-distributed keys;
#6. Distribution of new cipher keys using a trusted agent (in this case, the developed application must allow one of the instances to be configured as a trusted agent)

The developed application can work in Client Line Interface (CLI) mode or provide
A Graphical User Interface (GUI). Eventually, this system can be implemented for mobile devices, namely for the Android platform.
As already suggested above, the application should be able to work in client or server mode and ideally should 
let the user choose the mode every time it is started. If the chosen mode is the server mode, then the port 
number to be listened to should be requested, otherwise the IP address and destination port must be requested. 
An application running as a server should be able to provide a list of available users and provide a way to 
initiate dedicated connections between any two users for subsequent secrets exchange. 

#Work and knowledge can be strengthened through the implementation of the following functionalities:
#1. Use X.509 digital certificates in trade secrets that use RSA;
#2. Implement a public key infrastructure for the system and validate certificate chains in secrets exchanges that use RSA (eg, set a root certificate for the system and that is already embedded in the code or with the application, then generating digital certificates for each user of the system);
#3. Think about a correct way to provide digital certificates to users;
#4. Implement digital signature mechanisms to verify integrity in ephemeral key exchanges using Diffie-Hellman;
#5. Enable the choice of different cipher algorithms for Merkle Puzzles;
#6. Enable the selection of different hash functions for PBKDF2;
#7. Have a fairly complete help and be simple to use. Think of a way to attack the system (a failure of its implementation) and give it a section in the report.


