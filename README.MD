# OSVT: an Osquery extension 
## Overview 
OSVT is an Osquery extension written in Python that collects file hashes and submits them to Virus Total (VT) using VT's API. This will allow the user to determine malicious files on a system with high confidence. For more information, refer to my blog post: https://blog.imrhunter.xyz/osvt/ 

## Setup 
1. Osquery installation:
``` bash
  $ echo "deb [arch=amd64] https://pkg.osquery.io/deb deb main" | sudo tee /etc/apt/sources.list.d/osquery.list
  $ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
  $ sudo apt-get update
  $ sudo apt-get install osquery
  $ osqueryi --version # Check installation
```
2. Python3 installation
``` bash
  $ sudo apt update
  $ sudo apt install python3
  $ python3 --version # Check installation
```
3. Pip3 installation
``` bash
  $ sudo apt install -y python3-pip
```
4. Virus Total API installation
 ``` bash
  $ pip3 install virustotal-api
```

5. Osquery SDK installation
``` bash
  $ pip3 install osquery 
```
6. Obtain Virus Total API key
  * Registry on VirusTotal Community at https://www.virustotal.com/gui/join-us.
  * Sign in to the registered account and navigate to the menu (on the top right corner.) Click on the API to obtain the Virus Total Community API key.
## Usage
1. Osquery interactive shell 
  `$ osqueryi --nodisable-extensions`
2. Obtain Osquery extension socket path by ruuning the following command
  `osquery> SELECT value FROM osquery_flags WHERE name = 'extensions_socket';`
  * Copy the extension path
3. Run the extension
  Open a new terminal tab
  `$ python3 osvt.py --socket <the extension path from step 2> `
4. Extension in action 
  Switch back to Osquery's interactive shell 
  `osquery> select * from osvt;`
5. Switch back to the Python3 terminal and specifiy the directory as an input.
6. Obtain the results from osquery's interactive shell.
