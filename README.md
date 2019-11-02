# inds 
##UNSTABLE RELEASE

An (IN)line (D)hcp (S)poofer for stealth MITM attacks  on dhcp infrastructure.

Currently only linux supported.



### Installation:

Clone project.
```sh
git clone https://github.com/stralsundsecurity/inds
```

Create virtual python environment "env" with required packages.
```sh
cd inds
python3 -m venv env
. env/bin/activate
pip3 install -r python_requirements
```

The project is now ready to be built and run.

#### Build:

```sh
cd src
python3 setup.py build_ext --inplace
```

#### Run:

```sh
cd src
python3 inds.py --dhcp-server-mac aa:bb:cc:dd:ee:ff --new-subnet-mask 255.255.0.0 --new-gateway 192.168.0.144
```

For help, type:
```sh
python3 inds.py --help
```

NOTE: The flow of DHCP messages heavily depends on used hardware and software.
It might be, that clients in your network use an incompatible to this implementation dhcp message scheme.

Currently only changes in subnet mask and default gateway are supported (only one gateway).
Also only one DHCP server is supported.

All parameters must be provided.

### From the developer:

This project is meant to be more an extended proof of concept,
rather than a ready to use application. 
I know, that the code is not too good, to be honest, it is horrible… 
This is not due to a lack of will of the developer, 
but more due to a lack of experience and time
(this is my second python program I have ever written). 
There are many places in the code, that are bad 
in terms of performance and software architecture (some of them are even marked in the code, some not). 

I ask the user for understanding and invite him, or her to improve this program, 
add new features and make it more robust and performant.

Enjoy it :)
