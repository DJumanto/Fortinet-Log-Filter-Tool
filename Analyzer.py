import pandas as pd
import re
import datetime
'''
TODO
ADD MULTIPLE IN/OUT PORT FILTERING #DONE
ADD MULTIPLE IN/OUT IP FILTERING
ADD NON INCLUDED PORT
ADD NON INCLUDED IP
ADD SPECIFIC HEADER OUTPUT
ADD SORT BY HEADER
ADD VERIFIER IF FOR IP AND PORT FORMAT (xxx.xxx.xxx.xxx), 1-65535
'''
class Analyzer:
    def __init__(self, datacaptured):
        self.datacaptured = pd.read_csv(datacaptured, header=None)
        self.headers = []
        self.src_ip = []
        self.dst_ip = []
        self.dst_port = []
        self.src_port = []
        self.info = lambda x,y: print('\033[32m'+f'{x:<20}'+'\033[0m', end=y)
        self.alert = lambda x,y: print('\033[31m'+f'{x}'+'\033[0m', end=y)
        self.warning = lambda x,y: print('\033[33m'+f'{x}'+'\033[0m', end=y)
        self.SetHeaders()
        self.CleanData()
    
    def SetHeaders(self):
        try:
            for column in self.datacaptured.columns:
                for i in self.datacaptured[column].unique():
                    if not pd.isna(i):
                        i = i.split("=")[0] if "=" in i else i
                        i.replace("\"", "")
                        self.headers.append(i)
                        break
            self.datacaptured = self.datacaptured.set_axis(self.headers,axis=1)
        except:
            self.alert("Error while setting headers from file", '')
            return
    
    def CleanData(self):
        try:
            for i in range(len(self.datacaptured)):
                for j in self.datacaptured.columns:
                    if pd.notna(self.datacaptured.at[i, j]):
                        self.datacaptured.at[i, j] = self.datacaptured.at[i, j].split('=')[1] if '=' in self.datacaptured.at[i, j] else self.datacaptured.at[i, j]
                        self.datacaptured.at[i, j] = self.datacaptured.at[i,j].replace("\"","")
            self.datacaptured['data_timestamp'] = pd.to_datetime(self.datacaptured['data_timestamp'])
        except Exception as e:
            self.alert("Error while Cleaning Data With Error:", '\n')
            self.alert(e, '\n')
            return
    
    def GetHeaders(self):
        self.info("Here're the existing header in the data:", "\n")
        for i in range(len(self.headers)):
            if self.headers[i] is not None:
                self.info(f'{i + 1}. {self.headers[i]}',"\t\t")
                if (i + 1) % 3 == 0:
                    print()
        if len(self.headers) % 3 != 0:
            print()


    def SetSrcIPAddress(self):
        try:
            print("List All IP Addresses with comma sperator; ex(1.1.1.1,2.2.2.2,3.3.3.3)")
            ip_addresses = input(":>>>> ")
            ip_addresses = ip_addresses.split(",")
            spec_ip = self.datacaptured[self.datacaptured['src_ip'].isin(ip_addresses)]
            if(len(spec_ip)):
                self.src_ip = ip_addresses
                self.info(f"Incoming IP Address Has Been Set to {self.src_ip}", '\n')
            else:
                self.warning("Such incoming IP Address Not Found", '\n')
        except Exception as e:
            self.alert("Error while setting source ip address with error: ", '\n')
            self.alert(e, '\n')

    def SetDstIPAddress(self):
        try:
            print("List All IP Addresses with comma sperator; ex(1.1.1.1,2.2.2.2,3.3.3.3)")
            ip_addresses = input(":>>>> ")
            ip_addresses = ip_addresses.split(",")
            spec_ip = self.datacaptured[self.datacaptured['dst_ip'].isin(ip_addresses)]
            if(len(spec_ip)):
                self.dst_ip = ip_addresses
                self.info(f"Destination IP Address Has Been Set to {self.dst_ip}", '\n')
            else:
                self.warning("Such Destination IP Address Not Found", '\n')
        except:
            self.alert("Error while setting source ip address", '\n')

    def SetDstPort(self):
        try:
            print("List All port with comma separator; ex(21,80,443)")
            port = input(":>>>> ")
            port = port.split(",")
            spec_port = self.datacaptured[self.datacaptured['dst_port'].isin(port)]
            if(len(spec_port)):
                self.dst_port = port
                self.info(f"Destination Port Has Been Set to {self.dst_port}", '\n')
            else:
                self.warning("Such Destination Port Not Found", '\n')
        except Exception as e:
            self.alert("Error while setting source dst address with error:", '\n')
            self.alert(e, '\n')

    def SetSrcPort(self):
        try:
            print("List All port with comma separator; ex(21,80,443)")
            port = input(":>>>> ")
            port = port.split(",")
            spec_port = self.datacaptured[self.datacaptured['src_port'].isin(port)]
            if(len(spec_port)):
                self.src_port = port
                self.info(f"Destination Port Has Been Set to {self.src_port}", '\n')
            else:
                self.warning("Such Destination Port Not Found", '\n')
        except Exception as e:
            self.alert("Error while setting source src port address with error:", '\n')
            self.alert(e, '\n')

    def ExportData(self):
        try:
            opt = input("Do you want to export as CSV? (y/n): ")
            self.info("Here're the data you have filtered: ", '\n')
            data = self.GetFinalData()
            if opt == 'y':
                data.to_csv('output/filtered_data.csv', index=False)
            else:
                data.to_excel('output/filtered_data.xlsx', index=False)
            self.info("Data Exported Successfully", '\n')
        except Exception as e:
            self.alert("Error while exporting data with error:", '\n')
            self.alert(e, '\n')
            return

    def GetFinalData(self):
        output = self.datacaptured.copy()
        if(self.src_ip != ""):
            output = output[output['src_ip'] == self.src_ip]
        if(self.dst_ip != ""):
            output = output[output['dst_ip'] == self.dst_ip]
        if(self.dst_port != ""):
            output = output[output['dst_port'] == self.dst_port]
        return output
    
    def GetDataSummary(self):
        return self.datacaptured.head()
            

