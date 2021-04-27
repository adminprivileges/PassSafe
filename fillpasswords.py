import pyodbc

students = ['ABELIN','amazhar','bdalber','beagee','bedmunds','bfagan','bjollie','bwilliams12','caryoung','cavrett','chasullivan','dbrienzo','deodunn','dgregory','drand','dwright4','erowens','ETFISHER','ffullwood','ghammond','hurhodes','iryans','jaellison','jamparker','KADWILLIAMS','KBRYANT2','KCHAMBERS','lvanputte','MTAKATS','NMORGAN','SHADIXON','shobley','tburnett']

pw_dict = {'1':['Facebook', 'FacebookUsername', 'FacebookPassword'], '2':['Instagram', 'InstagramUsername', 'Instagram Password'], '3':['BankAccount', 'BankUser', 'BankPass'], '4':['School', 'SchoolUsername', 'SchoolPassword'], '5':['Email', 'EmailAddress', 'EmailPassword']}

conn = pyodbc.connect(f"DRIVER=ODBC Driver 17 for SQL Server; SERVER=192.168.4.145; DATABASE=Passsafe; UID=SA; PWD=ARMv1998yo;")
cursor = conn.cursor()         


pw_list = list(pw_dict.keys())
for student in students:
    for pw in pw_list:
        #cursor.execute(f"INSERT INTO passwords(label, username, password, auth_username) VALUES(\'{pw_dict[pw][0]}\', \'{pw_dict[pw][1]}\', \'{pw_dict[pw][2]}\', \'{student}\')")
        print(f"INSERT INTO passwords(label, username, password, auth_username) VALUES(\'{pw_dict[pw][0]}\', \'{pw_dict[pw][1]}\', \'{pw_dict[pw][2]}\', \'{student}\')")
conn.commit()
conn.close()