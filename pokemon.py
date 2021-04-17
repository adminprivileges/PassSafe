import requests, re, sqlite3, pyodbc
from bs4 import BeautifulSoup
try:
    conn = pyodbc.connect(
        f"DRIVER=ODBC Driver 17 for SQL Server; SERVER=192.168.4.145; DATABASE=Passsafe; UID=SA; PWD=######;"
    )
    #Initialize the cursor Object
    cursor = conn.cursor()         
    #poke_table_create = f"""CREATE TABLE IF NOT EXISTS pokemon(
    #poke_id integer PRIMARY KEY,
    #poke_name text NOT NULL,
    #poke_type text NOT NULL,
    #poke_desc text NOT NULL          
    #)"""
    #cursor.execute(poke_table_create)
    #I know theres more pokemon, but i dont want more than 550
    for x in range(84,551):
        poke_url = f"https://pokemon.gameinfo.io/en/pokemon/{x}" 
        page = requests.get(poke_url) #Request html for whole page
        soup = BeautifulSoup(page.content, 'html.parser') #make it pretty
        poke_name = soup.find_all(class_="title") #name is populates in the title class
        poke_name = poke_name[0].find("h1") 
        poke_name = poke_name.text.strip() #There's a LOT of whitespace around the output
        poke_type = soup.find(class_="large-type")
        #I used class name instead of the text field because i was able do better with less code
        poke_type = re.findall("POKEMON_TYPE_[A-Z]*", str(poke_type)) 
        poke_type = poke_type[0][13:] #Remove POKEMON_TYPE_
        poke_desc = soup.find_all(class_="description")
        poke_desc = poke_desc[1].text.strip().replace("'", "") #single quotes in the string confuses SQL
        #if len(poke_desc) > 128:
        #    poke_desc = f"\"{poke_desc[1:120]}\""
        poke_insert_logic = f"""INSERT INTO pokemon(pokedex_id, name, type, description) VAlUES('{x}', '{poke_name}', '{poke_type}', '{poke_desc[1:-1]}')\n"""
        print(poke_insert_logic)
        cursor.execute(poke_insert_logic)
        #testfile = open('testtext.txt', 'a+')
        #testfile.write(poke_insert_logic)
        #testfile.close()
except sqlite3.Error as e: 
    print(e) 

finally:
    conn.commit() #your db will be empty without this
    conn.close()

