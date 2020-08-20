from __future__ import print_function
import sqlite3
from sqlite3 import Error
import requests
import pandas as pd
import os
import csv
import time
from tqdm import tqdm
import sys, getopt
import codecs
import warnings
import deepsecurity
from deepsecurity.rest import ApiException
from pprint import pprint
import json
import pyfiglet
from openpyxl import Workbook
from datetime import datetime

'''Function to call Qualys API For Vulnerability Scan List Module'''
def QualysScanAPI(act, stat):
    print ('############################################ScanListAPIFunction########################################')
    headers = {
    'X-Requested-With': 'QualysApiExplorer',
    }
    data = {
      'action': act,
      'state': stat,
      '': ''
    }
    response = requests.post('https://qualysapi.qg2.apps.qualys.eu/api/2.0/fo/scan/', headers=headers, data=data, auth=(qname, qpass))
    return response.content
    #val=response.content
    #return val

'''Qualys User details API'''

def QualysUserAPI():
    print ('Calling Qualys User API to Get Current User Status.......###UserAPIFunction###')
    headers = {
    'X-Requested-With': 'QualysApiExplorer',
    }
    data = {
      '': ''
    }
    response = requests.post('https://qualysguard.qg2.apps.qualys.eu/msp/user_list.php', headers=headers, data=data, auth=(qname, qpass))
    return response.content
    

'''Qualys Report Template API'''
def QualysReportTemplateAPI():
    print ('Calling Qualys Report Template ID for Generating Report...####TemplateAPIFunction###')
    headers = {
    'X-Requested-With': 'QualysApiExplorer',
    }
    data = {
        'action': 'launch',
        'template_id': '1111111',
        'output_format': 'csv',
        'report_type': 'Scan',
        '': ''
    }
    response = requests.post('https://qualysguard.qg2.apps.qualys.eu/api/2.0/fo/report/', headers=headers, data=data, auth=(qname, qpass))
    #print response.content
    import xml.etree.ElementTree as ET
    root = ET.fromstring(response.content)
    ReportID = 0
    for elem in root.iter(tag='VALUE'):
            ReportID = elem.text
            print(ReportID)
    time.sleep(10)
    return ReportID
    print ('Qualys has launched a full report with ID ', ReportID)

'''Qualys Report Download API'''

def QualysReportDownloadAPI():
    if os.path.exists("qualys_initial.csv"):
      os.remove("qualys_initial.csv")
      
    if os.path.exists("qualys_final.csv"):
      os.remove("qualys_final.csv")
    headers = {
    'X-Requested-With': 'QualysApiExplorer',
    }
    ReportID=QualysReportTemplateAPI()
    print ('Qualys Downloading Report .... Hold on Tight its going to take few minutes ...###DownloadFunc###')
    print ('Downloading Qualys Report with ID', ReportID)
    while (True):
        time.sleep(40)
        data = {
            'action': 'fetch',
            'id': ReportID,
            '': ''
        }
        response = requests.post('https://qualysguard.qg2.apps.qualys.eu/api/2.0/fo/report/', headers=headers, data=data, auth=(qname, qpass))
        Code = 0
        r = response.headers['Content-Type']    
        if(r == 'text/xml;charset=UTF-8'):
            Code = 1  
        if(Code == 0):
            break
            
    f = open('qualys_initial.csv', "w", encoding='utf-8')
    f.write(response.text)
    f.close()
    print ('Writing CSV File for Qualys')
    with open('qualys_initial.csv', 'r') as inp, open('qualys_final.csv', 'w') as out :
       reader = csv.reader(inp)
       writer = csv.writer(out)
       for row in tqdm(reader):
        length = len(row)
        #print(length)
        if length > 10:
            writer.writerow(row)       
    df = pd.read_csv("qualys_final.csv")
    #print(df)
#Sample Function to call QualysScanAPI('list', 'Running')

def DeepSec_Api():
    print ('Connecting to Deep Security Platform ...###Calling Deep Security API###')
    if not sys.warnoptions:
        warnings.simplefilter("ignore")
    configuration=deepsecurity.Configuration()
    configuration.host="https://app.deepsecurity.trendmicro.com:443/api"
    #print ('deeptoken', deeptoken)
    dee=deeptoken
    print ('Fetching endpoint information using Access Key :', dee)
    configuration.api_key['api-secret-key']=dee

    api_instance=deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
    api_version='v1'
    expand_options=deepsecurity.Expand()
    expand_options.add(expand_options.none)
    expand=expand_options.list()
    overrides=False

    try:
        api_response=api_instance.list_computers(api_version,expand=expand,overrides=overrides)
        #pprint(api_response)
    except ApiException as e:
        print("Exception: %s",e)
    #sqlmain()
    try:
        conn = sqlmain()
        c = conn.cursor()
        print ('Downloading Report from Deep Security Platform ...###Calling Deep Security API###')
        for item in tqdm(api_response.computers):
            sql = f' INSERT INTO DeepSecurity(host_name, agent_version, computer_status, last_agent_communication, anti_malware, last_ip_used) ' \
                  f'VALUES(?, ?, ?, ?, ?, ?) '
            cur = conn.cursor()

            # Prepare data to insert
            list_array = []
            host_name = item.host_name if item.host_name else 'None';
            agent_version = item.agent_version if item.agent_version else 'None';
            computer_status = item.computer_status if item.computer_status else 'None';
            last_agent_communication = str(item.last_agent_communication) if item.last_agent_communication else 'None';
            anti_malware = item.anti_malware if item.anti_malware else 'None';
            last_ip_used = item.last_ip_used if item.last_ip_used else 'None';
            list_array.extend((host_name, agent_version, computer_status, last_agent_communication, anti_malware, last_ip_used))

            # execute insert query
            c.execute(sql, list_array)
            conn.commit()
            inserted_id = cur.lastrowid
            #print(inserted_id)
    except Error as e:
        print(e)
    finally:
        if conn:
            conn.close()

''' Create Database if not exists in current folder'''
def sqlmain():
    def create_connection(db_file):
        """ create a database connection to a SQLite database """
        conn = None
        try:
            conn = sqlite3.connect(db_file)
            print(sqlite3.version)        
        except Error as e:
            print(e)
        return conn


    def create_table(conn, create_table_sql):
        """ create a table from the create_table_sql statement
        :param conn: Connection object
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """
        try:
            c = conn.cursor()
            c.execute(create_table_sql)
        except Error as e:
            print(e)

    sql_create_VulnScan = """ CREATE TABLE IF NOT EXISTS VulnerabilityScan (
                                            TITLE text PRIMARY KEY,
                                            USER_LOGIN text NOT NULL,
                                            LAUNCH_DATETIME text,
                                            DURATION text,
                                            PROCESSING_PRIORITY text,
                                            PROCESSED int,
                                            TARGET text
                                        ); """

    sql_create_users = """CREATE TABLE IF NOT EXISTS User_Details (                                     
                                        USER_ID integer NOT NULL PRIMARY KEY,
                                        FIRSTNAME text,
                                        LASTNAME text,
                                        TITLE text,
                                        PHONE text,
                                        EMAIL text,
                                        USER_STATUS text,
                                        CREATION_DATE integer,
                                        USER_LOGIN text,
                                        LAST_LOGIN_DATE integer,
                                        USER_ROLE text
                                    );"""
    sql_create_deepsec = """ CREATE TABLE IF NOT EXISTS DeepSecurity (
                                            host_name text, agent_version text, computer_status text, last_agent_communication text, anti_malware text, last_ip_used text
                                        ); """
    conn = create_connection(os.path.realpath('Qualys.db'))
    if conn is not None:
        create_table(conn, sql_create_VulnScan)

        create_table(conn, sql_create_users)
        
        create_table(conn, sql_create_deepsec)
    else:
        print("Error! cannot create the database connection.")
    return conn

def WriteCSVData():
    df = pd.read_csv("qualys_final.csv")
    #print(df)
    conn = sqlmain()
    c = conn.cursor()
    df.to_sql('VulnerabilityDatabase', conn, if_exists='replace', index = True)
    conn.commit()
    conn.close()
    
def WriteData():
    response = QualysScanAPI('list', 'Finished')
    response1 = QualysUserAPI()
    import xml.etree.ElementTree as ET
    root = ET.fromstring(response)
    REF=[]
    TYPE=[]
    TITLE=[]
    USER_LOGIN=[]
    LAUNCH_DATETIME=[]
    DURATION=[]
    TARGET=[]
    for elem in root.iter(tag='REF'):
        REF.append(elem.text)
    #	print(*REF)

    for elem in root.iter(tag='TYPE'):
            TYPE.append(elem.text)

    for elem in root.iter(tag='TITLE'):
            TITLE.append(elem.text)
    #	print(*TITLE)
            
    for elem in root.iter(tag='USER_LOGIN'):
            USER_LOGIN.append(elem.text)
            
    for elem in root.iter(tag='LAUNCH_DATETIME'):
            LAUNCH_DATETIME.append(elem.text)
            
    for elem in root.iter(tag='DURATION'):
            DURATION.append(elem.text)
            
    for elem in root.iter(tag='TARGET'):
            TARGET.append(elem.text)
#conveting lists into dataframes USING PANDAS
    conn = sqlmain()
    df = pd.DataFrame(list(zip(REF, TYPE, TITLE, USER_LOGIN, LAUNCH_DATETIME, DURATION, TARGET)), columns=['Ref', 'TYPE', 'TITLE', 'USER_LOGIN', 'LAUNCH_DATETIME', 'DURATION', 'TARGET'])
    print(df)
    df.to_sql('VulnerabilityScan', conn, if_exists='replace', index = True)
    conn.commit()
    conn.close()

    root1 = ET.fromstring(response1)
    USER_ID=[]
    FIRSTNAME=[]
    LASTNAME=[]
    TITLE=[]
    PHONE=[]
    EMAIL=[]
    USER_STATUS=[]
    CREATION_DATE=[]
    USER_LOGIN=[]
    LAST_LOGIN_DATE=[]
    USER_ROLE=[]
    
    for elem in root1.iter(tag='USER_ID'):
        USER_ID.append(elem.text)
        #print USER_ID

    for elem in root1.iter(tag='FIRSTNAME'):
        FIRSTNAME.append(elem.text)
        #print FIRSTNAME

    for elem in root1.iter(tag='LASTNAME'):
        LASTNAME.append(elem.text)
        #print LASTNAME
    for elem in root1.iter(tag='TITLE'):
        TITLE.append(elem.text)
        #print TITLE
    for elem in root1.iter(tag='PHONE'):
        PHONE.append(elem.text)
        #print PHONE
    for elem in root1.iter(tag='EMAIL'):
        EMAIL.append(elem.text)
        #print EMAIL
    for elem in root1.iter(tag='USER_STATUS'):
        USER_STATUS.append(elem.text)
        #print USER_STATUS
    for elem in root1.iter(tag='CREATION_DATE'):
        CREATION_DATE.append(elem.text)
       #print CREATION_DATE
    for elem in root1.iter(tag='USER_LOGIN'):
        USER_LOGIN.append(elem.text)
        #print USER_LOGIN
    for elem in root1.iter(tag='LAST_LOGIN_DATE'):
        LAST_LOGIN_DATE.append(elem.text)
        #print LAST_LOGIN_DATE
    for elem in root1.iter(tag='USER_ROLE'):
        USER_ROLE.append(elem.text)
        #print USER_ROLE
#conveting lists into dataframes USING PANDAS
    conn = sqlmain()
    df1 = pd.DataFrame(list(zip(USER_ID, FIRSTNAME, LASTNAME, TITLE, PHONE, EMAIL, USER_STATUS, CREATION_DATE, USER_LOGIN, LAST_LOGIN_DATE, USER_ROLE)), columns=['USER_ID', 'FIRSTNAME', 'LASTNAME', 'TITLE', 'PHONE', 'EMAIL', 'USER_STATUS', 'CREATION_DATE', 'USER_LOGIN', 'LAST_LOGIN_DATE', 'USER_ROLE'])
    print(df1)
    df1.to_sql('User_Details', conn, if_exists='replace', index = True)
    conn.commit()
    conn.close()

def main():
    ascii_banner = pyfiglet.figlet_format("Sec-Automation!")
    print(ascii_banner)
    argv = sys.argv[1:]
    global qname
    global qpass
    global deeptoken
    deeptoken = ''
    qname = ''
    qpass = ''
    try:
      opts, args = getopt.getopt(argv,"h:u:p:d:")
    except getopt.GetoptError:
      print ('ScriptNamme.py -u <Qualys_qname> -p <Qualys_password> -d <deepsecurity Token>')
      sys.exit(2)

    for opt, arg in opts:
      if opt == '-h':
         print ('ScriptNamme.py -u <Qualys_username> -p <Qualys_Password> -d <deepsecurity Token>')
         sys.exit()
      elif opt in ("-u"):
         qname = arg
      elif opt in ("-p"):
         qpass = arg
      elif opt in ("-d"):
          deeptoken = arg
    print ('Qualys Username is "', qname)
    print ('Qualys password is "', qpass)
    print ('Deep Security Token "', deeptoken)
    #QualysReportTemplateAPI()
    QualysReportDownloadAPI()
    WriteData()
    WriteCSVData()
    DeepSec_Api()
    exit()
    
if __name__ == '__main__':
    main()
