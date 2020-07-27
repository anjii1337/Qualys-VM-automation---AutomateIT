import sqlite3
from sqlite3 import Error
import requests
import datetime
import pandas as pd
import os
import time
import csv

'''Formating datetime'''
readableDateTime = datetime.datetime.fromtimestamp(1593234749).isoformat()
print(readableDateTime)

'''Function to call Qualys API For Vulnerability Scan List Module'''
def QualysScanAPI(act, stat):
    headers = {
    'X-Requested-With': 'QualysApiExplorer',
    }
    data = {
      'action': act,
      'state': stat,
      '': ''
    }
    response = requests.post('https://qualysapi.qg2.apps.qualys.eu/api/2.0/fo/scan/', headers=headers, data=data, auth=('username', 'password'))
    '''if response.status_code == 200:
        print('Success!')
        print (response.content)
    elif response.status_code == 404:
        print('Not Found.')'''
    return response.content
  

'''Qualys User details API'''

def QualysUserAPI():
    headers = {
    'X-Requested-With': 'QualysApiExplorer',
    }
    data = {
      '': ''
    }
    response = requests.post('https://qualysguard.qg2.apps.qualys.eu/msp/user_list.php', headers=headers, data=data, auth=('username', 'password'))
    '''if response.status_code == 200:
        print('Success!')
        print (response.content)
    elif response.status_code == 404:
        print('Not Found.')'''
    return response.content

'''Qualys Report Template API'''
def QualysReportTemplateAPI():
    headers = {
    'X-Requested-With': 'QualysApiExplorer',
    }
    data = {
        'action': 'launch',
        'template_id': 'xxxxx',
        'output_format': 'csv',
        'report_type': 'Scan',
        '': ''
    }
    response = requests.post('https://qualysguard.qg2.apps.qualys.eu/api/2.0/fo/report/', headers=headers, data=data, auth=('username', 'password'))
    '''if response.status_code == 200:
        print('Success!')
        print (response.content)
    elif response.status_code == 404:
        print('Not Found.')'''
    import xml.etree.ElementTree as ET
    root = ET.fromstring(response.content)
    ReportID = 0
    for elem in root.iter(tag='VALUE'):
            ReportID = elem.text
            #print(ReportID)
    return ReportID

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
    print '############################################DownloadFunc################'
    print ReportID
    while(True):
        time.sleep(50)
        data = {
            'action': 'fetch',
            'id': ReportID,
            '': ''
        }
        response = requests.post('https://qualysguard.qg2.apps.qualys.eu/api/2.0/fo/report/', headers=headers, data=data, auth=('username', 'password'))
        Code = 0
        r = response.headers['Content-Type']
            
        if(r == 'text/xml;charset=UTF-8'):
            Code = 1
            
        if(Code == 0):
            break
        
    data = response.text
    print data
    f = open('qualys_initial.csv', "w", encoding='utf-8')
    f.write(response.text)
    f.close()
    with open('qualys_initial.csv', 'r') as inp, open('qualys_final.csv', 'w') as out :
       reader = csv.reader(inp)
       writer = csv.writer(out)
       for row in reader:
        length = len(row)
        #print(length)
        if length > 10:
            writer.writerow(row)       
    df = pd.read_csv("qualys_final.csv")
    print(df)

#Sample Function to call QualysScanAPI('list', 'Running')

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

    conn = create_connection(os.path.realpath('Qualys.db'))
    if conn is not None:
        create_table(conn, sql_create_VulnScan)

        create_table(conn, sql_create_users)
    else:
        print("Error! cannot create the database connection.")
    return conn

def WriteCSVData():
    df = pd.read_csv("qualys_final.csv")
    print(df)
    conn = sqlmain()
    c = conn.cursor()
    df.to_sql('VulnerabilityDatabase', conn, if_exists='replace', index = True)
    conn.commit()
    conn.close()
    
def WriteData():
    response = QualysScanAPI('list', 'Finished')
    response1 = QualysUserAPI()
    print response
    print response1
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
        print EMAIL
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

if __name__ == '__main__':
    #sqlmain()
    WriteData()
    #QualysReportTemplateAPI()
    QualysReportDownloadAPI()
    WriteCSVData()
    exit
