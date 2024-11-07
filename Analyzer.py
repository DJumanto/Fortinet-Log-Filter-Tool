import pandas as pd
import re
import datetime
import os
'''
TODO
ADD MULTIPLE IN/OUT PORT FILTERING #DONE
ADD MULTIPLE IN/OUT IP FILTERING #DONE
ADD EXCLUDED PORT #DONE
ADD EXCLUDED IP #DONE
ADD SPECIFIC HEADER OUTPUT #DONE
ADD VERIFIER IF FOR IP AND PORT FORMAT (xxx.xxx.xxx.xxx), 1-65535
DEBUG
'''
class Analyzer:
    def __init__(self, datacaptured):
        self.datacaptured = pd.read_csv(datacaptured, header=None)
        self.headers = []
        self.src_ip = []
        self.dst_ip = []
        self.dst_port = []
        self.src_port = []
        self.exclude_src_port = []
        self.exclude_dst_port = []
        self.exclude_src_ip = []
        self.exclude_dst_ip = []
        self.output_cols = []
        self.info = lambda x,y: print('\033[32m'+f'{x:<20}'+'\033[0m', end=y)
        self.alert = lambda x,y: print('\033[31m'+f'{x}'+'\033[0m', end=y)
        self.pressenterinput = lambda : input('\033[33m'+"Press Enter to Continue"+'\033[0m')
        self.clear = lambda : os.system('cls') if os.name == 'nt' else os.system('clear')
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
        except Exception as e:
            self.HandleException("Error while setting headers with error:", e)
    
    def CleanData(self):
        try:
            for i in range(len(self.datacaptured)):
                for j in self.datacaptured.columns:
                    if pd.notna(self.datacaptured.at[i, j]):
                        self.datacaptured.at[i, j] = self.datacaptured.at[i, j].split('=')[1] if '=' in self.datacaptured.at[i, j] else self.datacaptured.at[i, j]
                        self.datacaptured.at[i, j] = self.datacaptured.at[i,j].replace("\"","")
            self.datacaptured['data_timestamp'] = pd.to_datetime(self.datacaptured['data_timestamp'], errors='coerce')
        except Exception as e:
            self.HandleException("Error while cleaning data with error:", e)
    
    def GetHeaders(self):
        self.info("Here're the existing header in the data:", "\n")
        for i in range(len(self.headers)):
            if self.headers[i] is not None:
                self.info(f'{i + 1}. {self.headers[i]}',"\t\t")
                if (i + 1) % 3 == 0:
                    print()
        if len(self.headers) % 3 != 0:
            print()

    def SetOutputHeaders(self):
        try:
            self.GetHeaders()
            print("List All Headers with comma sperator; ex(1,2,3)")
            headers = input(":>>>> ")
            headers = headers.split(",")
            self.output_cols = [self.headers[int(i) - 1] for i in headers]
            return True
        except Exception as e:
            self.HandleException("Error while setting output headers with error:", e)
            return False

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
                raise Exception("Such Source IP Address Not Found")
        except Exception as e:
            self.HandleException("Error while setting source ip address with error:", e)

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
                raise Exception("Such Destination IP Address Not Found", '\n')
        except Exception as e:
            self.HandleException("Error while setting destination ip address with error:", e)

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
                raise Exception("Such Destination Port Not Found", '\n')
        except Exception as e:
            self.HandleException("Error while setting destination port with error:", e)

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
                raise Exception("Such Destination Port Not Found", '\n')
        except Exception as e:
            self.HandleException("Error while setting source port with error:", e)

    def ExportData(self):
        try:
            opt = input("Do you want to set spesific header output? (y/n): ")
            if opt == 'y':
                if(not self.SetOutputHeaders()):
                    raise Exception("Error while setting output")
            data = self.GetFinalData()
            if data.empty:
                raise Exception("No Data Found", '\n')
            else:
                current_date = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
                opt = input("Do you want to export as CSV? (y/n): ")
                self.info("Here're the data you have filtered: ", '\n')
                if opt == 'y':
                    data.to_csv(f'output/filtered_data_{current_date}.csv', index=False)
                else:
                    data.to_excel(f'output/filtered_data_{current_date}.xlsx', index=False)
                self.info("Data Exported Successfully", '\n')
        except Exception as e:
            self.HandleException("Error while exporting data with error:", e)


    def GetFinalData(self):
        try:
            output = self.datacaptured.copy()
            if(self.exclude_dst_ip != []):
                output = output[~output['dst_ip'].isin(self.exclude_dst_ip)]
            if(self.exclude_src_ip != []):
                output = output[~output['src_ip'].isin(self.exclude_src_ip)]
            if(self.exclude_dst_port != []):
                output = output[~output['dst_port'].isin(self.exclude_dst_port)]
            if(self.exclude_src_port != []):
                output = output[~output['src_port'].isin(self.exclude_src_port)]
            if(self.src_ip != []):
                output = output[output['src_ip'].isin(self.src_ip)]
            if(self.dst_ip != []):
                output = output[output['dst_ip'].isin(self.dst_ip)]
            if(self.dst_port != []):
                output = output[output['dst_port'].isin(self.dst_port)]
            if(self.src_port != []):
                output = output[output['src_port'].isin(self.src_port)]
            if(self.output_cols != []):
                output = output[self.output_cols]
            return output
        except Exception as e:
            self.HandleException("Error while getting final data with error:", e)

    def PrintCurrentFilter(self):
        self.info("Here're the current filter: ", '\n')
        try:
            if len(self.src_ip):
                self.info("Incoming IP Address:", "\n")
                for i in self.src_ip:
                    self.info(f"\t{i}", "\n")
            if len(self.dst_ip):
                self.info("Destination IP Address:", "\n")
                for i in self.dst_ip:
                    self.info(f"\t{i}", "\n")
            if len(self.src_port):
                self.info("Source Port:", "\n")
                for i in self.src_port:
                    self.info(f"\t{i}", "\n")
            if len(self.dst_port):
                self.info("Destination Port:", "\n")
                for i in self.dst_port:
                    self.info(f"\t{i}", "\n")
        except Exception as e:
            self.HandleException("Error while printing current filter with error:", e)

    def ExcludeDstPort(self):
        try:
            print("List All port with comma separator; ex(21,80,443)")
            port = input(":>>>> ")
            port = port.split(",")
            self.exclude_dst_port = port
            self.info(f"excluded Port Has Been Set to {self.exclude_dst_port}", '\n')
        except Exception as e:
            self.HandleException("Error while excluding port with error:", e)
    
    def ExcludeSrcPort(self):
        try:
            print("List All port with comma separator; ex(21,80,443)")
            port = input(":>>>> ")
            port = port.split(",")
            self.exclude_src_port = port
            self.info(f"excluded Port Has Been Set to {self.exclude_src_port}", '\n')
        except Exception as e:
            self.HandleException("Error while excluding port with error:", e)
    
    def ExcludeDstIP(self):
        try:
            print("List All IP Addresses with comma sperator; ex(1.1.1.1,2.2.2.2,4.4.4.4)")
            ip_addresses = input(":>>>> ")
            ip_addresses = ip_addresses.split(",")
            self.exclude_dst_ip = ip_addresses
            self.info(f"excluded IP Has Been Set to {self.exclude_dst_ip}", '\n')
        except Exception as e:
            self.HandleException("Error while excluding ip  with error:", e)
    
    def ExcludeSrcIP(self):
        try:
            print("List All IP Addresses with comma sperator; ex(1.1.1.1,2.2.2.2,4.4.4.4)")
            ip_addresses = input(":>>>> ")
            ip_addresses = ip_addresses.split(",")
            self.exclude_src_ip = ip_addresses
            self.info(f"excluded IP Has Been Set to {self.exclude_src_ip}", '\n')
        except Exception as e:
            self.HandleException("Error while excluding ip  with error:", e)

    
    def ResetFilter(self):
        self.src_ip = []
        self.dst_ip = []
        self.dst_port = []
        self.src_port = []
        self.exclude_dst_port = []
        self.exclude_src_port = []
        self.exclude_dst_ip = []
        self.exclude_src_ip = []
        self.output_cols = []
        self.clear()
        self.info("Filter has been reset", '\n')
        self.pressenterinput()
    
    def HandleException(self, message, e):
        self.clear()
        self.alert(message, '\n')
        self.alert(e, '\n')
        self.pressenterinput()


    def GetDataSummary(self):
        return self.datacaptured.head()
            

