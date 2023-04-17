# CSC-380 CHAT APP PROJECT WITH AUTHENTICATION, ENCRYPTION, AND CRYPTOGRAPHY

## Project description

This project implements a chat app with end-to-end encryption and authentication for secure user communication. To ensure that all messages are safe and cannot be intercepted or interfered with by unauthorized parties, the app employs a variety of cryptographic methods and algorithms. Additionally, the application has implemented software security features to protect against common software vulnerabilities.

## Getting Started

**WARNING : The project is only compilable on a linux system.**

**Step 1:** If you are running on a windows or ios system, please make sure to [download](https://geo.mirror.pkgbuild.com/iso/2023.03.01/archlinux-2023.03.01-x86_64.iso) the harch iso file in order to install linux os on a virtual machine.

**Step 2:** Follow the instructions on this [link](https://itsfoss.com/install-arch-linux-virtualbox/), it is a step tutorial for installing linux os on a virtual machine using the harch iso file downloaded earlier.

**_Installation_**

1. On your virtual machine, open a console and cloine the repository : `git clone git@github.com:MarkusCDev/csc380-p1.git`
2. Change the directory to the folder where the repository will be downloaded : `cd csc380-p1`
3. compile the app: `make`. If you happen to have an issue compiling the app, please make sure you clear the existing Make file by running `make clean`
4. Run the app: `./chat -l` to listen on a server. The default server is 1337
5. In another console, type the following command `./chat -p 133` to connect to the server.
6. Have fun ! :)

Note: Your virtual machine MUST be git ready before being able to clone the repository. The following [link](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/checking-for-existing-ssh-keys) will show you how to set it up.

## Features:

- End-to-end encryption: Messages are encrypted using AES by the sender before being sent and decrypted by the recipient.
- Message integrity: To ensure message integrity and avoid tampering, message authentication codes (MACs) are implemented.
- Key exchange: Diffie-Hellman key exchange is used to securely exchange encryption keys between users.
- To securely exchange encryption keys between users, RSA public-key cryptography is used.

## Technologies used:

- For increased performance and security, code is written in C and C++ and compiled with GCC.
- OpenSSL, a powerful open-source toolbox for developing cryptographic protocols and algorithms.

## Vulnerability

The vulnerability associated with a TCP SYN-ACK response was exploited using a DOS python script paired with tools in a kali debian environment. By using fragmented scanning, instead of just pinging, and utilizing the -Pn command in addition to -v on nmap to debug, it was determined that there was multiple ways to circumvent the chat and connect to listening host. We patched one issue that would close the port immediately to prevent connection. On an incomplete project, it is determined to be possible to use DOS to connect, although the connection would close once the next request would come in. IN addition, the port that is open must be made known in order to successfully simulate the attack, as well as the host IP. Different vulnerabilities can be carried out afterwards, with the earmark "escape vulnerabilities" meant to escape the hypervisor and access the host's main PC. What is achievable is manipulating the TCP port and closing the port forcefully. Additionally, on the barebones implementation, running the commands to DOS or slow the connection before the listening command is run starts the chat function

## Constribution

Contributions are encouraged! Please file any bug reports or feature requests on the GitHub repository as problems.
Note that this project is a class assignment and many more features could be implemented to make it more complete.

## Credits

This app was created by the followings:

- [Markus Chmiel](https://github.com/MarkusCDev)
- [Kevin Pechersky](https://github.com/BigboiKesha)
- [Meng Wai Chan](https://github.com/mengwaichan)
- [Oumar Barry](https://github.com/OumB2021)
