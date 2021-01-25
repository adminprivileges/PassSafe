#Open Source Password management software written by Thaddeus Koeing
import tkinter as tk
#Parent clas, initializing the application
class PassSafe(tk.Tk): 
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        #Creating the tkinter basic container
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        #Empty Doct for later page identification
        self.frames = {}
        #Creating the tkinter frame for each app, might change with lines 34-38
        #TODO: Change with lines 35-39 because i think this is causing conflict with the image 
        for F in (StartPage, PageOne):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(StartPage) #Always start on homepage

    #Necessary function to switch frames using buttons later
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
    
    def login_funct(self, username, password, label):
        if username == "Thaddeus" and password == "Koenig":
            print("Access Granted")
            self.show_frame(PageOne)
        else:
            label['text']= 'Username or Password Incorrect Please Try Again'

#Passsafe Login Class
class StartPage(tk.Frame):
    #Authenticaton function
    #TODO: hash password entry, match against password, then ass showframe function to loginbutton 
    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        canvas = tk.Canvas(self, height=700, width=800)
        canvas.pack()

        frame = tk.Frame(self, bg='#80c1ff', bd=5)
        frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')  
        
        self.username = tk.Entry(frame, font=40, text='Username')
        self.username.place(relwidth=0.40, relheight=1)
        self.username.insert(0, 'Username')

        self.password = tk.Entry(frame, font=40, text='Password')
        self.password.place(relwidth=0.40, relx= 0.41,relheight=1)
        self.password.insert(0, 'Password')

        button = tk.Button(frame, text="Login", font=40, command=lambda: controller.login_funct(self.username.get(), self.password.get(), self.label))
        button.place(relx=0.82, relheight=1, relwidth=0.18)
        #Creating a lowerframe to fill and work with 
        lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.6, anchor='n')
        self.label = tk.Label(lower_frame, text='PassSafe Password Manager')
        self.label.place(relwidth=1, relheight=.2)
        #TODO: Figure out why the hell my image isnt showing anymore
        background_image = tk.PhotoImage(file='safe_icon.png')
        background_image = background_image.subsample(2, 2)
        background_image_label = tk.Label(lower_frame, image=background_image) 
        background_image_label.place(rely=.2, relwidth=1, relheight=.8)
    
class PageOne(tk.Frame):
 def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        canvas = tk.Canvas(self, height=700, width=800)
        canvas.pack()
        frame = tk.Frame(self, bg='#80c1ff', bd=5)
        frame.place(relx=0.5, rely=0.1, relwidth=.75, relheight=0.1, anchor='n')
        self.label = tk.Label(frame, font=40, text="Welcome to PassSafe, please choose an option")
        self.label.place(relwidth=1,relheight=1)
        lower_frame = tk.Frame(self, bg='#80c1ff', bd=10)
        lower_frame.place(relx=0.5, rely=0.25, relwidth=0.75, relheight=0.25, anchor='n')
        self.button1 = tk.Button(lower_frame, text='View Passwords')
        self.button1.place(relwidth=1, relheight=.45)
        self.button2 = tk.Button(lower_frame, text='Edit Passwords')
        self.button2.place(rely=.50, relwidth=1, relheight=.45)



app = PassSafe()
app.mainloop()