# ShoPort
Shodan Based Fast Portscanner

``` 
Its an shodan based passive port scanner. [Just add your shodan api key in source code]

```

### Usage

``` bash
python3 shoport.py -sip 172.16.1.2 # To scan a single ip address
python3 shoport.py -ipl ip.list    # To scan a list of ip address
python3 shoport.py -ir 192.168.1.1/24 # To scan an range of ip address
python3 shoport.py -hn google.com # To scan an single host adress

```
