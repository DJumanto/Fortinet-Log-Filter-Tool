# Fortinet Log Viewer
This code will help you understand the output log from fortinet

## Usage
```bash
python3 checker.py -h
usage: checker.py [-h] datacaptured

information list

positional arguments:
  datacaptured  data captured csv file

options:
  -h, --help    show this help message and exit
```
### Example
```bash
python3 checker.py log.csv 
```
### Menu
```bash
Welcome to Fortinet Analyzer Log Viewer

1. Print Headers Exists
2. Print Data Summary
3. Set Source IP Address
4. Set Destination IP Address
5. Set Destination Port
6. Set Source Port
7. Print Current Filter
8. Reset Filter
9. Extract Output Data
10. Exit
```