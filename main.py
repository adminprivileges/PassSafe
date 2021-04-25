#Open Source Password management software written by Thaddeus Koeing
import tkinter as tk
from tkinter import ttk
import time, sqlite3, os, string, random, pyodbc, random
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet

#Parent clas, initializing the application
class PassSafe(tk.Tk): 
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        #Creating  DB files if it doesnt exist
        #self.create_db("passsafe")
        #Creating the tkinter basic container
        self.title('PassSafe - Password Manager')
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        #Global Username variable
        global user_auth_global
        user_auth_global = ""
        #Empty Doct for later page identification
        self.frames = {}
        #Creating the tkinter frame for each app, might change with lines 34-38
        #TODO: Change with lines 35-39 because i think this is causing conflict with the image 
        for F in (StartPage, CreateUser, MainMenu, ViewPass, EditPass, AddPass, ModPass, DelPass, ViewCard, EditCard, AddCard, ModPass, DelCard):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(StartPage) #Always start on homepage
    def database_open(self, dblogic):
        self.conn = None
        try:
            self.conn = pyodbc.connect(f"DRIVER=ODBC Driver 17 for SQL Server; SERVER=192.168.4.145; DATABASE=Passsafe; UID=SA; PWD=######;")
            self.cursor = self.conn.cursor()         
            self.cursor.execute(dblogic)
        except sqlite3.Error as e:
            print(e)
        finally:
            if self.conn:
                self.conn.commit()
                self.conn.close()
    '''
    #Create the DB if it doesnt exist
    def create_db(self, db_name):
        self.conn = None
        try:
            self.conn = sqlite3.connect(f"/home/th/code/python/passsafe/{db_name}.db")
            cursor = self.conn.cursor()    
            #if not exists (select * from sysobjects where name='authentication' and xtype='U')     
            authentication_table_create = f"""CREATE TABLE authentication(
            name text PRIMARY KEY,
            hash blob NOT NULL,
            salt1 blob NOT NULL,
            salt2 blob NOT NULL          
            )"""
            cursor.execute(authentication_table_create)
            return cursor.fetchall()
        except sqlite3.Error as e:
            print(e)
        finally:
            if self.conn:
                self.conn.close()
    '''
    #Necessary function to switch frames using buttons later
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
    #Authenticaton function
    #TODO: hash password entry, match against password, then ass showframe function to loginbutton 
    def login_funct(self, username, password, label):
        login_conn = pyodbc.connect(f"DRIVER=ODBC Driver 17 for SQL Server; SERVER=192.168.4.145; DATABASE=Passsafe; UID=SA; PWD=######;")
        logg = login_conn.cursor()
        logg_logic= f'''SELECT hash, salt2 FROM auth_user WHERE username = \'{username}\''''
        key_1 = logg.execute(logg_logic)
        key_1 = logg.fetchone()
        salt2 = key_1[1]
        salt2 = bytes(salt2, 'utf-8')
        #print(f" the salt {salt2} is type {type(salt2)}")
        key = self.create_scrypt(password, salt2)[0]
        key = str(key)
        key = key[2:-1]
        #print(f"Key = {key}, key1 = {key_1[0]} ")
        if str(key) == str(key_1[0]):          
            label['text']= 'Access Granted'
            self.mainmenu_edits(username)
            self.show_frame(MainMenu)
            global user_auth_global
            user_auth_global = username
            
        else:
            label['text']= 'Username or Password Incorrect Please Try Again'
    #Long story short tkinter loads all pages at boot, so any user interaction needs to be done after the fact, the other classes are for style not function
    def mainmenu_edits(self, username):
        MainMenu.mainmenu_label['text'] = f"Welcome to PassSafe {username}, please choose an option"
    def viewpass_edits(self, username):
        conn = pyodbc.connect(f"DRIVER=ODBC Driver 17 for SQL Server; SERVER=192.168.4.145; DATABASE=Passsafe; UID=SA; PWD=######;")
        cursor = conn.cursor()
        cursor.execute(f" SELECT label,username,password from passwords WHERE auth_username=\'{username}\'")
        rows = cursor.fetchall()    
        for row in rows:
            print(row) 
            ViewPass.tree.insert("", tk.END, values=row) 
        conn.close()
    def viewcard_edits(self, username):
        conn = pyodbc.connect(f"DRIVER=ODBC Driver 17 for SQL Server; SERVER=192.168.4.145; DATABASE=Passsafe; UID=SA; PWD=######;")
        cursor = conn.cursor()
        cursor.execute(f"""
        SELECT payment_cards.label,payment_cards.card_number,payment_cards.card_type,payment_cards.zip_code,payment_cards.sec_code,payment_cards.card_name, debit_cards.pin
        FROM payment_cards
        Full Outer Join debit_cards on payment_cards.label=debit_cards.debit_label AND payment_cards.auth_username = \'{user_auth_global}\'
        """)
        rows = cursor.fetchall()    
        for row in rows:
            print(row) 
            ViewCard.tree.insert("", tk.END, values=row) 
        conn.close()
    def poke_generate(self, label, username):
        conn = pyodbc.connect(
        f"DRIVER=ODBC Driver 17 for SQL Server; SERVER=192.168.4.145; DATABASE=Passsafe; UID=SA; PWD=######;"
        )
        cursor = conn.cursor() 
        while True:
            random_pokemon = random.randint(0,549)
            if random_pokemon != 83: break
        cursor.execute(f'SELECT * from pokemon where pokedex_id = \'{random_pokemon}\'')
        pok = cursor.fetchone()
        #chooses a ranom word from pokemon description
        rando = random.randint(0, len(pok[3].split())-1)
        poke_password = f'{pok[1]}-{pok[2]}-{pok[3].split()[rando]}'
        AddPass.addpass_password_enrty.insert(0,f"{poke_password}")
        #updates password table
        cursor.execute(f"INSERT INTO passwords(label, username, password, auth_username) VALUES(\'{label}\', \'{username}\', \'{poke_password}\', \'{user_auth_global}\')")
        #update populates table
        cursor.execute(f'INSERT into populates(pokedex_id, label, auth_username, desc_idex) VALUES(\'{pok[0]}\', \'{label}\', \'{user_auth_global}\',\'{rando}\')')
        conn.commit() #your db will be empty without this
        conn.close()
    #Password DB logic
    def addpass_sql(self, label, username, password):
        dblogic = f"INSERT INTO passwords(label, username, password, auth_username) VALUES(\'{label}\', \'{username}\', \'{password}\', \'{user_auth_global}\')"
        self.database_open(dblogic)
    def addcard_sql(self,label,card_number,card_type,zip_code,sec_code,card_name,pin):
        dblogic = f"INSERT INTO payment_cards(label,card_number,card_type,zip_code,sec_code,card_name,auth_username) VALUES(\'{label}\',\'{card_number}\',\'{card_type}\',\'{zip_code}\',\'{sec_code}\',\'{card_name}\',\'{user_auth_global}\')"
        self.database_open(dblogic)
        if card_type.lower() == "debit":
            dblogic1 = f"INSERT into debit_cards(debit_label, debit_username, pin) VALUES(\'{label}\', \'{user_auth_global}\', \'{pin}\') "
            self.database_open(dblogic1)
        else:
            pass
    
    def modpass_sql(self, label, username, password):
        dblogic = f"UPDATE passwords SET username=\'{username}\', password=\'{password}\' WHERE label=\'{label}\' AND auth_username=\'{user_auth_global}\'"
        self.database_open(dblogic)
    def modcard_sql(self, label,card_number,card_type,zip_code,sec_code,card_name,pin):
        dblogic = f"UPDATE payment cards set card_number= \'{card_number}\',card_type = \'{card_type}\',zip_code = \'{zip_code}\',sec_code = \'{sec_code}\',card_name= \'{card_name}\' WHERE label = \'{label}\' AND auth_username=\'{user_auth_global}\'"
        self.database_open(dblogic)
        if card_type.lower() == "debit":
            dblogic1 = f"UPDATE debit_cards set pin = \'{pin}\' WHERE debit_label = \'{label}, \' AND debit_username = \'{user_auth_global}\'" 
            self.database_open(dblogic1)
    def delpass_sql(self, label):
        dblogic = f"DELETE from passwords WHERE label=\'{label}\' AND auth_username=\'{user_auth_global}\'"
        self.database_open(dblogic)
    def delcard_sql(self, label):
        dblogic = f"DELETE from payment_cards WHERE label=\'{label}\' AND auth_username=\'{user_auth_global}\'"
        self.database_open(dblogic)
    #Create a User then store their credentials in the auth db, and make them a table in passsafe db
    def create_user(self, username, password, label):
        self.password = password
        #TODO: Make Table in Cred Database
        auth_conn = pyodbc.connect(f"DRIVER=ODBC Driver 17 for SQL Server; SERVER=192.168.4.145; DATABASE=Passsafe; UID=SA; PWD=######;")
        auth = auth_conn.cursor()
        #Queries the database to see if the user already has a table
        #TODO: Since im using an auth database i need to change this to not query for a table with that name but query the authdb for the name in the primary key field
        auth.execute(f" SELECT count(username) FROM auth_user WHERE username=\'{{username}}\' ")
        if auth.fetchone()[0]==1 :
            label['text'] = "This user already exists"
        #Check if pw meets length requirements
        elif len(self.password) < 16: 
            label['text'] = "Password must be at least 16 characters"
        #Populates table in Authdb
        else:
            try: 
                hash, salt2 = self.create_scrypt(self.password) 
                salt1 = self.create_pkdf(self.password)[1]
                salt1 = str(salt1)[2:-1]
                salt2 = str(salt2)[2:-1]
                #redo hash to work with mysql
                print(f'Hash Before: {hash} Hash Type: {type(hash)}')
                hash = str(hash)
                hash = hash[2:-1]
                #hash = f'{hash[0]}\'{hash[1:-1]}\'\''
                print(f'Hash After {hash}')
                #TODO: Call the new_key fuction and get the values to populate db, then do it=
                print(f' INSERT INTO auth_user(username, hash, salt1, salt2) VALUES(\'{username}\', \'{hash}\', \'{salt1}\', \'{salt2}\')')
                auth.execute(f'INSERT INTO auth_user(username, hash, salt1, salt2) VALUES(\'{username}\', \'{hash}\', \'{salt1}\', \'{salt2}\')')
                label['text'] = "User Created. Please go back to login"
            except sqlite3.Error as e: 
                print(e) 
            finally: 
                auth_conn.commit()
                auth_conn.close()
    #TODO: DB extra parameter for username, if username = none
    def create_scrypt(self, password, salt2="none"):
        self.salt2 = salt2
        #print(f"The password is {password}, the salt is {self.salt2}")
        if self.salt2 == "none": 
            #variable type must be bytes
            N=16
            start_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
            self.salt2 = bytes(start_str, 'utf-8')
        else:
            #Insert DB logic to pull user salt
            pass
        password = password.encode()  # Convert to type bytes
        #inializing scrypt hash
        scrypt = Scrypt(
            salt=self.salt2,
            length=32,
            n=2**14,
            r=8,
            p=1,
        ) 
        #key used to authenticate the user
        self.scrypt_key = base64.urlsafe_b64encode(scrypt.derive(password))  # Can only use kdf once
        return self.scrypt_key, self.salt2
    def create_pkdf(self, password, salt1="none"):
        self.salt1 = salt1
        if self.salt1 == "none":
            #variable type must be bytes
            N=16
            start_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
            self.salt1 = bytes(start_str, 'utf-8')

        else:
            #Insert DB logic to pull user salt
            pass
        pbkdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=self.salt1,
        iterations=100000,
        )
        password = password.encode()  # Convert to type bytes
        #key used to encrypt/decrypt the db cred values
        self.pbkdf2_key = base64.urlsafe_b64encode(pbkdf.derive(password))  # Can only use kdf once
        return self.pbkdf2_key, self.salt1
    def encrypt(self, key, message):
        f = Fernet(key)
        encrypted = f.encrypt(message)  # Encrypt the bytes. The returning object is of type bytes
        return encrypted
    def decrypt(self, key, encrypted):
        f = Fernet(key)
        decrypted = f.decrypt(encrypted)  # Decrypt the bytes. The returning object is of type bytes
        decrypted = str(decrypted)[2:-1]  # Strip b''
        

#Passsafe Login Class
class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        startpage_canvas = tk.Canvas(self, height=700, width=800)
        startpage_canvas.pack()
        #Blue border, top of the window
        startpage_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        startpage_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')  
        self.username = tk.Entry(startpage_frame, font=40)
        self.username.place(relwidth=0.30, relheight=1)
        self.username.insert(0, 'Username') #Makes the window say username
        self.password = tk.Entry(startpage_frame, font=40)
        self.password.place(relwidth=0.30, relx= 0.31,relheight=1)
        self.password.insert(0, 'Password')#Makes the window say password
        #Login button, has function has to be called anonymously or it wont work
        startpage_button = tk.Button(startpage_frame, text="Login", font=40, command=lambda: controller.login_funct(self.username.get(), self.password.get(), self.startpage_label))
        startpage_button.place(relx=0.62, relheight=1, relwidth=0.18)
        #Create User 
        startpage_create_button = tk.Button(startpage_frame, text="Create User", font=40, command=lambda: controller.show_frame(CreateUser))
        startpage_create_button.place(relx=0.82, relheight=1, relwidth=0.18)
        #Creating a lowerframe to fill and work with 
        startpage_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        startpage_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.6, anchor='n')
        self.startpage_label = tk.Label(startpage_lower_frame, text='PassSafe Password Manager')
        self.startpage_label.place(relwidth=1, relheight=.2)
        #TODO: Figure out why the hell my image isnt showing anymore
        background_image = tk.PhotoImage(file='safe_icon.png')
        background_image = background_image.subsample(2, 2)
        background_image_label = tk.Label(startpage_lower_frame, image=background_image) 
        background_image_label.place(rely=.2, relwidth=1, relheight=.8)

class CreateUser(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        createuser_canvas = tk.Canvas(self, height=700, width=800)
        createuser_canvas.pack()
        #Blue border, top of the window
        createuser_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        createuser_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        createuser_label = tk.Label(createuser_frame, font=20, text="Enter Your User Information Here and Click Submit")
        createuser_label.place(relwidth=.80,relheight=1)
        createuser_return_button = tk.Button(createuser_frame, text='Back', command=lambda: controller.show_frame(StartPage))
        createuser_return_button.place(relx=.82, relwidth=.18,relheight=1)
        #Creating a lowerframe to fill and work with 
        createuser_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        createuser_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.6, anchor='n')
        #User input Objects
        #Username
        createuser_username_label = tk.Label(createuser_lower_frame, text='Username')
        createuser_username_label.place(relwidth=.48, relheight=.20)
        createuser_username_enrty = tk.Entry(createuser_lower_frame, font=40) 
        createuser_username_enrty.place(relx= .5, relwidth=.5, relheight=.20)
        #Password
        createuser_password_label = tk.Label(createuser_lower_frame, text='Password (must be at least 16 Characters)')
        createuser_password_label.place(rely=.25, relwidth=.48, relheight=.20)
        createuser_password_enrty = tk.Entry(createuser_lower_frame, font=40, show="*") 
        createuser_password_enrty.place(rely=.25,relx=.5 , relwidth=.5, relheight=.20)
        #Password Verification
        createuser_password_verify_label = tk.Label(createuser_lower_frame, text='Verify Password')
        createuser_password_verify_label.place(rely=.50, relwidth=.48, relheight=.20)
        createuser_password_verify_enrty = tk.Entry(createuser_lower_frame, font=40, show="*") 
        createuser_password_verify_enrty.place(rely=.50,relx=.5 , relwidth=.5, relheight=.20)
        #Submit Button
        createuser_submit_button = tk.Button(createuser_lower_frame, text='Submit', command=lambda: controller.create_user(createuser_username_enrty.get(), createuser_password_enrty.get(), createuser_label))
        createuser_submit_button.place(rely=.75, relwidth=.48, relheight=.20)

class MainMenu(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        mainmenu_canvas = tk.Canvas(self, height=700, width=800)
        mainmenu_canvas.pack()
        #Blue border, top of the window
        mainmenu_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        mainmenu_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        MainMenu.mainmenu_label = tk.Label(mainmenu_frame, font=40)
        MainMenu.mainmenu_label.place(relwidth=.80,relheight=1)
        self.mainmenu_button = tk.Button(mainmenu_frame, text="Log Out", font=40, command=lambda: controller.show_frame(StartPage))
        self.mainmenu_button.place(relx=0.82, relheight=1, relwidth=0.18)
        #Lower Frame
        mainmenu_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        mainmenu_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.50, anchor='n')
        self.mainmenu_button1 = tk.Button(mainmenu_lower_frame, text='View Passwords', command=lambda: [controller.show_frame(ViewPass), controller.viewpass_edits(user_auth_global)])
        self.mainmenu_button1.place(relwidth=1, relheight=.20)
        self.mainmenu_button2 = tk.Button(mainmenu_lower_frame, text='Edit Passwords', command=lambda: controller.show_frame(EditPass))
        self.mainmenu_button2.place(rely=.25, relwidth=1, relheight=.20)
        self.mainmenu_button3 = tk.Button(mainmenu_lower_frame, text='View Cards', command=lambda: [controller.show_frame(ViewCard), controller.viewcard_edits(user_auth_global)])
        self.mainmenu_button3.place(rely=.50, relwidth=1, relheight=.20)
        self.mainmenu_button4 = tk.Button(mainmenu_lower_frame, text='Edit Cards', command=lambda: controller.show_frame(EditCard))
        self.mainmenu_button4.place(rely=.75, relwidth=1, relheight=.20)

class ViewPass(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        viewpass_canvas = tk.Canvas(self, height=700, width=800)
        viewpass_canvas.pack()
        #Blue border, top of the window
        viewpass_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        viewpass_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.viewpass_label = tk.Label(viewpass_frame, font=40, text="These are the passwords you currently have saved ")
        self.viewpass_label.place(relwidth=.80,relheight=1)
        self.viewpass_button = tk.Button(viewpass_frame, text="Main Menu", font=40, command=lambda: [controller.show_frame(MainMenu), ViewPass.tree.delete(*ViewPass.tree.get_children())])
        self.viewpass_button.place(relx=0.82, relheight=1, relwidth=0.18)
        viewpass_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        viewpass_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.25, anchor='n')
        ViewPass.tree = ttk.Treeview(viewpass_lower_frame, column=("c1", "c2", "c3"), show='headings')
        ViewPass.tree.column("#1", anchor=tk.CENTER)
        ViewPass.tree.heading("#1", text="Label")
        ViewPass.tree.column("#2", anchor=tk.CENTER)
        ViewPass.tree.heading("#2", text="Username")
        ViewPass.tree.column("#3", anchor=tk.CENTER)
        ViewPass.tree.heading("#3", text="Password")
        ViewPass.tree.pack()
        #ViewPass.viewpass_label = tk.Label(viewpass_lower_frame, font=40, anchor="nw")
        #ViewPass.viewpass_label.place(relwidth=1,relheight=1)

class EditPass(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        editpass_canvas = tk.Canvas(self, height=700, width=800)
        editpass_canvas.pack()
        #Blue border, top of the window
        editpass_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        editpass_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.editpass_label = tk.Label(editpass_frame, font=40, text="Would you like to Add, Modify or Delete Your Inventory ")
        self.editpass_label.place(relwidth=.80,relheight=1)
        self.editpass_button = tk.Button(editpass_frame, text="Main Menu", font=40, command=lambda: controller.show_frame(MainMenu))
        self.editpass_button.place(relx=0.82, relheight=1, relwidth=0.18)
        editpass_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        editpass_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.4, anchor='n')
        self.editpass_button1 = tk.Button(editpass_lower_frame, text='Add Passwords', command=lambda: controller.show_frame(AddPass))
        self.editpass_button1.place(relwidth=1, relheight=.30)
        self.editpass_button2 = tk.Button(editpass_lower_frame, text='Modify Passwords', command=lambda: controller.show_frame(ModPass))
        self.editpass_button2.place(rely=.35, relwidth=1, relheight=.30)
        self.editpass_button3 = tk.Button(editpass_lower_frame, text='Delete Passwords', command=lambda: controller.show_frame(DelPass))
        self.editpass_button3.place(rely=.70, relwidth=1, relheight=.30)

class AddPass(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        addpass_canvas = tk.Canvas(self, height=700, width=800)
        addpass_canvas.pack()
        #Blue border, top of the window
        addpass_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        addpass_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.addpass_label = tk.Label(addpass_frame, font=40, text="Add New Passwords Here")
        self.addpass_label.place(relwidth=.80,relheight=1)
        self.addpass_button = tk.Button(addpass_frame, text="Main Menu", font=40, command=lambda: controller.show_frame(MainMenu))
        self.addpass_button.place(relx=0.82, relheight=1, relwidth=0.18)
        addpass_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        addpass_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.25, anchor='n')
        #Label
        self.addpass_label_label = tk.Label(addpass_lower_frame, text ='Label')
        self.addpass_label_label.place(relwidth=.48, relheight=.20)
        self.addpass_label_enrty = tk.Entry(addpass_lower_frame, font=40) 
        self.addpass_label_enrty.place(relx= .5, relwidth=.5, relheight=.20)
        #Usename
        self.addpass_username_label = tk.Label(addpass_lower_frame, text ='Username')
        self.addpass_username_label.place(rely=.25, relwidth=.48, relheight=.20)
        self.addpass_username_enrty = tk.Entry(addpass_lower_frame, font=40) 
        self.addpass_username_enrty.place(rely=.25,relx=.5 , relwidth=.5, relheight=.20)
        #Password
        self.addpass_password_label = tk.Label(addpass_lower_frame, text='Password')
        self.addpass_password_label.place(rely=.50, relwidth=.48, relheight=.20)
        AddPass.addpass_password_enrty = tk.Entry(addpass_lower_frame, font=40, show="*") 
        AddPass.addpass_password_enrty.place(rely=.50,relx=.5 , relwidth=.5, relheight=.20)
        #Need a password? create function that allows user to press a button that sets off pokemon function and fill the password entry
        self.addpass_pokemon_button = tk.Button(addpass_lower_frame, text='Gen Password/Submit', command= lambda: controller.poke_generate(self.addpass_label_enrty.get(), self.addpass_username_enrty.get()))
        self.addpass_pokemon_button.place(rely=.75, relwidth=.48, relheight=.20)
        #submit
        self.addpass_submit_button = tk.Button(addpass_lower_frame, text='Submit', command=lambda: controller.addpass_sql(self.addpass_label_enrty.get(), self.addpass_username_enrty.get(), self.addpass_password_enrty.get()))
        self.addpass_submit_button.place(rely=.75, relx=.5, relwidth=.48, relheight=.20)

class ModPass(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        modpass_canvas = tk.Canvas(self, height=700, width=800)
        modpass_canvas.pack()
        #Blue border, top of the window
        modpass_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        modpass_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.modpass_label = tk.Label(modpass_frame, font=40, text="Modify Passwords Here")
        self.modpass_label.place(relwidth=.80,relheight=1)
        self.modpass_button = tk.Button(modpass_frame, text="Main Menu", font=40, command=lambda: controller.show_frame(MainMenu))
        self.modpass_button.place(relx=0.82, relheight=1, relwidth=0.18)
        modpass_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        modpass_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.25, anchor='n')
        #Label
        self.modpass_label_label = tk.Label(modpass_lower_frame, text ='Enter Label Identifier')
        self.modpass_label_label.place(relwidth=.48, relheight=.20)
        self.modpass_label_enrty = tk.Entry(modpass_lower_frame, font=40) 
        self.modpass_label_enrty.place(relx= .5, relwidth=.5, relheight=.20)
        #Username
        self.modpass_username_label = tk.Label(modpass_lower_frame, text='Enter Username')
        self.modpass_username_label.place(rely=.25, relwidth=.48, relheight=.20)
        self.modpass_username_enrty = tk.Entry(modpass_lower_frame, font=40) 
        self.modpass_username_enrty.place(rely=.25,relx=.5 , relwidth=.5, relheight=.20)
        #Password
        self.modpass_password_label = tk.Label(modpass_lower_frame, text='Enter Password')
        self.modpass_password_label.place(rely=.50, relwidth=.48, relheight=.20)
        self.modpass_password_enrty = tk.Entry(modpass_lower_frame, font=40, show="*") 
        self.modpass_password_enrty.place(rely=.50,relx=.5 , relwidth=.5, relheight=.20)
        #submit
        self.modpass_pokemon_button = tk.Button(modpass_lower_frame, text='Submit', command=lambda: controller.modpass_sql(self.modpass_label_enrty.get(), self.modpass_username_enrty.get(), self.modpass_password_enrty.get()))
        self.modpass_pokemon_button.place(rely=.75, relx=.5, relwidth=.48, relheight=.20)

class DelPass(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        delpass_canvas = tk.Canvas(self, height=700, width=800)
        delpass_canvas.pack()
        #Blue border, top of the window
        delpass_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        delpass_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.delpass_label = tk.Label(delpass_frame, font=40, text="Delete Passwords Here")
        self.delpass_label.place(relwidth=.80,relheight=1)
        self.delpass_button = tk.Button(delpass_frame, text="Main Menu", font=40, command=lambda: controller.show_frame(MainMenu))
        self.delpass_button.place(relx=0.82, relheight=1, relwidth=0.18)
        delpass_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        delpass_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.25, anchor='n')
        #Label
        self.delpass_label_label = tk.Label(delpass_lower_frame, text ='Enter Label Identifier')
        self.delpass_label_label.place(relwidth=.48, relheight=.20)
        self.delpass_label_enrty = tk.Entry(delpass_lower_frame, font=40) 
        self.delpass_label_enrty.place(relx= .5, relwidth=.5, relheight=.20)
        #submit
        self.delpass_pokemon_button = tk.Button(delpass_lower_frame, text='Submit', command=lambda: controller.delpass_sql(self.delpass_label_enrty.get()))
        self.delpass_pokemon_button.place(rely=.25, relx=.5, relwidth=.48, relheight=.20)

class ViewCard(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        viewcard_canvas = tk.Canvas(self, height=700, width=800)
        viewcard_canvas.pack()
        #Blue border, top of the window
        viewcard_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        viewcard_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.viewcard_label = tk.Label(viewcard_frame, font=40, text="These are the cards you currently have saved ")
        self.viewcard_label.place(relwidth=.80,relheight=1)
        self.viewcard_button = tk.Button(viewcard_frame, text="Main Menu", font=40, command=lambda: [controller.show_frame(MainMenu), ViewCard.tree.delete(*ViewCard.tree.get_children())])
        self.viewcard_button.place(relx=0.82, relheight=1, relwidth=0.18)
        viewcard_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        viewcard_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.5, anchor='n')
        ViewCard.tree = ttk.Treeview(viewcard_lower_frame, column=("c1", "c2", "c3", "c4", "c5", "c6", "c7"), show='headings')
        ViewCard.tree.column("#1", anchor=tk.CENTER)
        ViewCard.tree.heading("#1", text="Label")
        ViewCard.tree.column("#2", anchor=tk.CENTER)
        ViewCard.tree.heading("#2", text="Card Number")
        ViewCard.tree.column("#3", anchor=tk.CENTER)
        ViewCard.tree.heading("#3", text="Card Type")
        ViewCard.tree.column("#4", anchor=tk.CENTER)
        ViewCard.tree.heading("#4", text="Zip Code")
        ViewCard.tree.column("#5", anchor=tk.CENTER)
        ViewCard.tree.heading("#5", text="Sec Code")
        ViewCard.tree.column("#6", anchor=tk.CENTER)
        ViewCard.tree.heading("#6", text="Card Name")
        ViewCard.tree.column("#7", anchor=tk.CENTER)
        ViewCard.tree.heading("#7", text="PIN")
        ViewCard.tree.pack()
        #ViewCard.viewcard_label = tk.Label(viewcard_lower_frame, font=40, anchor="nw")
        #ViewCard.viewcard_label.place(relwidth=1,relheight=1)

class EditCard(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        editcard_canvas = tk.Canvas(self, height=700, width=800)
        editcard_canvas.pack()
        #Blue border, top of the window
        editcard_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        editcard_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.editcard_label = tk.Label(editcard_frame, font=40, text="Would you like to Add, Modify or Delete Your Inventory ")
        self.editcard_label.place(relwidth=.80,relheight=1)
        self.editcard_button = tk.Button(editcard_frame, text="Main Menu", font=40, command=lambda: controller.show_frame(MainMenu))
        self.editcard_button.place(relx=0.82, relheight=1, relwidth=0.18)
        editcard_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        editcard_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.4, anchor='n')
        self.editcard_button1 = tk.Button(editcard_lower_frame, text='Add Cards', command=lambda: controller.show_frame(AddCard))
        self.editcard_button1.place(relwidth=1, relheight=.30)
        self.editcard_button2 = tk.Button(editcard_lower_frame, text='Modify Cards', command=lambda: controller.show_frame(ModCard))
        self.editcard_button2.place(rely=.35, relwidth=1, relheight=.30)
        self.editcard_button3 = tk.Button(editcard_lower_frame, text='Delete Cards', command=lambda: controller.show_frame(DelCard))
        self.editcard_button3.place(rely=.70, relwidth=1, relheight=.30)

class AddCard(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        addcard_canvas = tk.Canvas(self, height=700, width=800)
        addcard_canvas.pack()
        #Blue border, top of the window
        addcard_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        addcard_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.addcard_label = tk.Label(addcard_frame, font=40, text="Add New Cards Here")
        self.addcard_label.place(relwidth=.80,relheight=1)
        self.addcard_button = tk.Button(addcard_frame, text="Main Menu", font=40, command=lambda: controller.show_frame(MainMenu))
        self.addcard_button.place(relx=0.82, relheight=1, relwidth=0.18)
        addcard_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        addcard_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.50, anchor='n')
        #Label
        self.addcard_label_label = tk.Label(addcard_lower_frame, text ='Label')
        self.addcard_label_label.place(relwidth=.48, relheight=.10)  
        self.addcard_label_enrty = tk.Entry(addcard_lower_frame, font=40) 
        self.addcard_label_enrty.place(relx= .5, relwidth=.5, relheight=.10)
        #Card Number
        self.addcard_card_numb_label = tk.Label(addcard_lower_frame, text ='CardNumber')
        self.addcard_card_numb_label.place(rely=.15, relwidth=.48, relheight=.10)
        self.addcard_card_numb_enrty = tk.Entry(addcard_lower_frame, font=40) 
        self.addcard_card_numb_enrty.place(rely=.15,relx=.5 , relwidth=.5, relheight=.10)
        #Card Type
        self.addcard_cardtype_label = tk.Label(addcard_lower_frame, text='Credit Or Debit')
        self.addcard_cardtype_label.place(rely=.30, relwidth=.48, relheight=.10)
        self.addcard_cardtype_enrty = tk.Entry(addcard_lower_frame, font=40) 
        self.addcard_cardtype_enrty.place(rely=.30,relx=.5 , relwidth=.5, relheight=.10)
        #Zip Code
        self.addcard_zip_label = tk.Label(addcard_lower_frame, text ='Zip Code')
        self.addcard_zip_label.place(rely=.45, relwidth=.48, relheight=.10)
        self.addcard_zip_enrty = tk.Entry(addcard_lower_frame, font=40) 
        self.addcard_zip_enrty.place(rely=.45,relx=.5 , relwidth=.5, relheight=.10)
        #Security Code
        self.addcard_card_sec_label = tk.Label(addcard_lower_frame, text ='Security Code')
        self.addcard_card_sec_label.place(rely=.60, relwidth=.48, relheight=.10) 
        self.addcard_card_sec_enrty = tk.Entry(addcard_lower_frame, font=40) 
        self.addcard_card_sec_enrty.place(rely=.60,relx=.5 , relwidth=.5, relheight=.10)
        #Card Name
        self.addcard_cardname_label = tk.Label(addcard_lower_frame, text='Name On Card')
        self.addcard_cardname_label.place(rely=.75, relwidth=.48, relheight=.10)
        self.addcard_cardname_enrty = tk.Entry(addcard_lower_frame, font=40) 
        self.addcard_cardname_enrty.place(rely=.75,relx=.5 , relwidth=.5, relheight=.10)
        #PIN
        self.addcard_pin_entry = tk.Entry(addcard_lower_frame, font=40)
        self.addcard_pin_entry.insert(0, 'Pin(N/A if credit)') 
        self.addcard_pin_entry.place(rely=.90, relwidth=.48, relheight=.10)
        #submit
        self.addcard_submit_button = tk.Button(addcard_lower_frame, text='Submit', command=lambda: controller.addcard_sql(self.addcard_label_enrty.get(), self.addcard_card_numb_enrty.get(), self.addcard_cardtype_enrty.get(), self.addcard_zip_enrty.get(), self.addcard_card_sec_enrty.get(), self.addcard_cardname_enrty.get(), self.addcard_pin_entry.get()))
        self.addcard_submit_button.place(rely=.90, relx=.5, relwidth=.48, relheight=.10)

class ModCard(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        modcard_canvas = tk.Canvas(self, height=700, width=800)
        modcard_canvas.pack()
        #Blue border, top of the window
        modcard_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        modcard_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.modcard_label = tk.Label(modcard_frame, font=40, text="Modify Cards Here")
        self.modcard_label.place(relwidth=.80,relheight=1)
        self.modcard_button = tk.Button(modcard_frame, text="Main Menu", font=40, command=lambda: controller.show_frame(MainMenu))
        self.modcard_button.place(relx=0.82, relheight=1, relwidth=0.18)
        modcard_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        modcard_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.25, anchor='n')
        #Label
        self.modcard_label_label = tk.Label(modcard_lower_frame, text ='Label')
        self.modcard_label_label.place(relwidth=.48, relheight=.10)  
        self.modcard_label_enrty = tk.Entry(modcard_lower_frame, font=40) 
        self.modcard_label_enrty.place(relx= .5, relwidth=.5, relheight=.10)
        #Card Number
        self.modcard_card_numb_label = tk.Label(modcard_lower_frame, text ='CardNumber')
        self.modcard_card_numb_label.place(rely=.15, relwidth=.48, relheight=.10)
        self.modcard_card_numb_enrty = tk.Entry(modcard_lower_frame, font=40) 
        self.modcard_card_numb_enrty.place(rely=.15,relx=.5 , relwidth=.5, relheight=.10)
        #Card Type
        self.modcard_cardtype_label = tk.Label(modcard_lower_frame, text='Credit Or Debit')
        self.modcard_cardtype_label.place(rely=.30, relwidth=.48, relheight=.10)
        self.modcard_cardtype_enrty = tk.Entry(modcard_lower_frame, font=40) 
        self.modcard_cardtype_enrty.place(rely=.30,relx=.5 , relwidth=.5, relheight=.10)
        #Zip Code
        self.modcard_zip_label = tk.Label(modcard_lower_frame, text ='Zip Code')
        self.modcard_zip_label.place(rely=.45, relwidth=.48, relheight=.10)
        self.modcard_zip_enrty = tk.Entry(modcard_lower_frame, font=40) 
        self.modcard_zip_enrty.place(rely=.45,relx=.5 , relwidth=.5, relheight=.10)
        #Security Code
        self.modcard_card_sec_label = tk.Label(modcard_lower_frame, text ='Security Code')
        self.modcard_card_sec_label.place(rely=.60, relwidth=.48, relheight=.10) 
        self.modcard_card_sec_enrty = tk.Entry(modcard_lower_frame, font=40) 
        self.modcard_card_sec_enrty.place(rely=.60,relx=.5 , relwidth=.5, relheight=.10)
        #Card Name
        self.modcard_cardname_label = tk.Label(modcard_lower_frame, text='Name On Card')
        self.modcard_cardname_label.place(rely=.75, relwidth=.48, relheight=.10)
        self.modcard_cardname_enrty = tk.Entry(modcard_lower_frame, font=40) 
        self.modcard_cardname_enrty.place(rely=.75,relx=.5 , relwidth=.5, relheight=.10)
        #PIN
        self.modcard_pin_entry = tk.Entry(modcard_lower_frame, font=40)
        self.modcard_pin_entry.insert(0, 'N/A') 
        self.modcard_pin_entry.place(rely=.90, relwidth=.48, relheight=.10)
        #submit
        self.modcard_submit_button = tk.Button(modcard_lower_frame, text='Submit', command=lambda: controller.modcard_sql(self.modcard_label_enrty.get(), self.modcard_card_numb_enrty.get(), self.modcard_cardtype_enrty.get(), self.modcard_zip_enrty.get(), self.modcard_card_sec_enrty.get(), self.modcard_cardname_enrty.get(), self.modcard_pin_entry.get()))
        self.modcard_submit_button.place(rely=.90, relx=.5, relwidth=.48, relheight=.10)

class DelCard(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        delcard_canvas = tk.Canvas(self, height=700, width=800)
        delcard_canvas.pack()
        #Blue border, top of the window
        delcard_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        delcard_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.delcard_label = tk.Label(delcard_frame, font=40, text="Delete Cards Here")
        self.delcard_label.place(relwidth=.80,relheight=1)
        self.delcard_button = tk.Button(delcard_frame, text="Main Menu", font=40, command=lambda: controller.show_frame(MainMenu))
        self.delcard_button.place(relx=0.82, relheight=1, relwidth=0.18)
        delcard_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        delcard_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.25, anchor='n')
        #Label
        self.delcard_label_label = tk.Label(delcard_lower_frame, text ='Enter Label Identifier')
        self.delcard_label_label.place(relwidth=.48, relheight=.20)
        self.delcard_label_enrty = tk.Entry(delcard_lower_frame, font=40) 
        self.delcard_label_enrty.place(relx= .5, relwidth=.5, relheight=.20)
        #submit
        self.delcard_pokemon_button = tk.Button(delcard_lower_frame, text='Submit', command=lambda: controller.delcard_sql(self.delcard_label_enrty.get()))
        self.delcard_pokemon_button.place(rely=.25, relx=.5, relwidth=.48, relheight=.20)       
        
app = PassSafe()
app.mainloop()

#https://www.youtube.com/watch?v=YXPyB4XeYLA&t=14975s
#https://github.com/flatplanet/Intro-To-TKinter-Youtube-Course/blob/master/database2.py
#https://charlesleifer.com/blog/encrypted-sqlite-databases-with-python-and-sqlcipher/
#https://stackoverflow.com/questions/22812134/how-to-clear-an-entire-treeview-with-tkinter#comment82282737_27068344
#https://www.activestate.com/resources/quick-reads/how-to-display-data-in-a-table-using-tkinter/
