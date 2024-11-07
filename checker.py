import pandas as pd
import argparse
from Analyzer import Analyzer
import os
import sys

def Init():
    parser = argparse.ArgumentParser(description='information list')
    parser.add_argument('datacaptured', type=str, help='data captured csv file')
    args = parser.parse_args()
    return args

def clear():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')

def Options(args):
    analyzer = Analyzer(args.datacaptured)
    while 1:
        print("\n\n=======================================")
        print("Welcome to Fortinet Analyzer Log Viewer\n")
        print("1. Print Headers Exists")
        print("2. Print Data Summary")
        print("3. Set Source IP Address")
        print("4. Set Destination IP Address")
        print("5. Set Destination Port")
        print("6. Set Source Port")
        print("7. Print Current Filter")
        print("8. Reset Filter")
        print("9. Extract Output Data")
        print("10. Exit")
        try:
            option = int(input("Choose an option: "))
            if option == 1:
                clear()
                analyzer.GetHeaders()
            elif option == 2:
                clear()
                summary = analyzer.GetDataSummary()
                print(summary, end="\n\n")
            elif option == 3:
                clear()
                analyzer.SetSrcIPAddress()
            elif option == 4:
                clear()
                analyzer.SetDstIPAddress()
            elif option == 5:
                clear()
                analyzer.SetDstPort()
            elif option == 6:
                clear()
                analyzer.SetSrcPort()
            elif option == 7:
                clear()
                analyzer.PrintCurrentFilter()
            elif option == 8:
                clear()
                analyzer.ResetFilter()
            elif option == 9:
                clear()
                analyzer.ExportData()
            elif option == 10:
                print("Goodbye!")
                return
            else:
                print("Invalid option")
        except Exception as e:
            clear()
            print(e)
            print("only take argument from 1 to 10")
            pass

if __name__ == '__main__':
    args = Init()
    Options(args)
    