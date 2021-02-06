#Open Source Password management software written by Thaddeus Koeing
import tkinter as tk
import time, sqlite3, os
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
        self.create_db("passsafe")
        #Creating the tkinter basic container
        self.title('PassSafe - Password Manager')
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        #Empty Doct for later page identification
        self.frames = {}
        #Creating the tkinter frame for each app, might change with lines 34-38
        #TODO: Change with lines 35-39 because i think this is causing conflict with the image 
        for F in (StartPage, CreateUser, MainMenu, ViewPass, EditPass):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(StartPage) #Always start on homepage
    #Create the DB if it doesnt exist
    def create_db(self, db_name):
        self.conn = None
        try:
            self.conn = sqlite3.connect(f"/home/th/code/python/passsafe/{db_name}.db")
        except sqlite3.Error as e:
            print(e)
        finally:
            if self.conn:
                self.conn.close()
    #Create table in passsafe db
    def create_table(self, conn, table_logic):
        try:
            c = conn.cursor()
            c.execute(table_logic)
        except sqlite3.Error as e:
            print(e)
        finally:
            if conn:
                conn.close()


    #Necessary function to switch frames using buttons later
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
    #Authenticaton function
    #TODO: hash password entry, match against password, then ass showframe function to loginbutton 
    def login_funct(self, username, password, label):
        #login_conn = sqlite3.connect(f"/home/th/code/python/passsafe/passsafe.db")
        #logg = login_conn.cursor()
        #logg.execute()
        #key = self.create_pkdf(password)[0]
        if username == "Thaddeus" and password == "Koenig":
            label['text']= 'Access Granted'
            self.mainmenu_edits(username)
            self.show_frame(MainMenu)
        else:
            label['text']= 'Username or Password Incorrect Please Try Again'
    #Long story short tkinter loads all pages at boot, so any user interaction needs to be done after the fact, the other classes are for style not function
    def mainmenu_edits(self, username):
        MainMenu.mainmenu_label['text'] = f"Welcome to PassSafe {username}, please choose an option"
    #Create a User then store their credentials in the auth db, and make them a table in passsafe db
    def create_user(self, username, password, label):
        self.password = password
        #TODO: Make Table in Cred Database
        auth_conn = sqlite3.connect(f"/home/th/code/python/passsafe/passsafe.db")
        auth = auth_conn.cursor()
        #Queries the database to see if the user already has a table
        auth.execute(f" SELECT count(name) FROM sqlite_master WHERE type='table' AND name=\'{{username}}\' ")
        if auth.fetchone()[0]==1 :
            label['text'] = "This user already exists"
        #Check if pw meets length requirements
        elif len(self.password) < 16:
            label['text'] = "Password must be at least 16 characters"
        #Populates table in Authdb
        else:
            hash, salt2= Crypto.create_scrypt(self.password) 
            salt1 = Crypto.create_pkdf(self.password)[1]
            #TODO: Call the new_key fuction and get the values to populate db, then do it
            self.create_table(auth_conn,f"""
            CREATE TABLE IF NOT EXISTS {username} (
            name text PRIMARY KEY,
            hash text NOT NULL,
            salt1 text NOT NULL,
            salt2 text NOT NULL          
            """)
            auth.execute(f''' INSERT INTO {username}(name,hash,salt1,salt2)
              VALUES({username},{hash},{salt1},{salt2}) ''')
            auth_conn.close()

class Crypto():
    def create_scrypt(self, password, salt2="none"):
        if salt2 == "none":
            self.salt2 = os.urandom(16)  #variable type must be bytes
        else:
            #Insert DB logic to pull user salt
            pass
        password = password.encode()  # Convert to type bytes
        #inializing scrypt hash
        scrypt = Scrypt(
            salt=self.salt2,
            length=128,
            n=2**14,
            r=8,
            p=1,
        )
        #key used to authenticate the user
        self.scrypt_key = base64.urlsafe_b64encode(scrypt.derive(password))  # Can only use kdf once
        return self.scrypt_key, self.salt2
    def create_pkdf(self, password, salt1=""):
        if salt1 == "none":
            self.salt1 = os.urandom(16)  #variable type must be bytes
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
        mainmenu_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        mainmenu_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.25, anchor='n')
        self.mainmenu_button1 = tk.Button(mainmenu_lower_frame, text='View Passwords', command=lambda: controller.show_frame(ViewPass))
        self.mainmenu_button1.place(relwidth=1, relheight=.45)
        self.mainmenu_button2 = tk.Button(mainmenu_lower_frame, text='Edit Passwords', command=lambda: controller.show_frame(EditPass))
        self.mainmenu_button2.place(rely=.50, relwidth=1, relheight=.45)

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
        self.viewpass_button = tk.Button(viewpass_frame, text="Main Menu", font=40, command=lambda: controller.show_frame(MainMenu))
        self.viewpass_button.place(relx=0.82, relheight=1, relwidth=0.18)
        viewpass_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        viewpass_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.25, anchor='n')
        
class EditPass(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        #Dictates the actual size of the window
        editpass_canvas = tk.Canvas(self, height=700, width=800)
        editpass_canvas.pack()
        #Blue border, top of the window
        editpass_frame = tk.Frame(self, bg='#80c1ff', bd=5)
        editpass_frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.editpass_label = tk.Label(editpass_frame, font=40, text="Would you like to Add, Modyfy or Delete Your Inventory ")
        self.editpass_label.place(relwidth=.80,relheight=1)
        self.editpass_button = tk.Button(editpass_frame, text="Main Menu", font=40, command=lambda: controller.show_frame(MainMenu))
        self.editpass_button.place(relx=0.82, relheight=1, relwidth=0.18)
        editpass_lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        editpass_lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.4, anchor='n')
        self.editpass_button1 = tk.Button(editpass_lower_frame, text='Add Passwords', command=lambda: controller.show_frame(ViewPass))
        self.editpass_button1.place(relwidth=1, relheight=.30)
        self.editpass_button2 = tk.Button(editpass_lower_frame, text='Modify Passwords', command=lambda: controller.show_frame(EditPass))
        self.editpass_button2.place(rely=.35, relwidth=1, relheight=.30)
        self.editpass_button3 = tk.Button(editpass_lower_frame, text='Delete Passwords', command=lambda: controller.show_frame(EditPass))
        self.editpass_button3.place(rely=.70, relwidth=1, relheight=.30)

        

app = PassSafe()
app.mainloop()

#https://www.youtube.com/watch?v=YXPyB4XeYLA&t=14975s
#https://github.com/flatplanet/Intro-To-TKinter-Youtube-Course/blob/master/database2.py
#https://charlesleifer.com/blog/encrypted-sqlite-databases-with-python-and-sqlcipher/
#TODO: Create "Create user button", add database logic
