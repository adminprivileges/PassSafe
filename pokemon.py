import requests, re, sqlite3
from bs4 import BeautifulSoup
try:
    conn = sqlite3.connect(f"/home/th/code/python/passsafe/passsafe.db")
    #Initialize the cursor Object
    cursor = conn.cursor()         
    poke_table_create = f"""CREATE TABLE IF NOT EXISTS pokemon(
    poke_id integer PRIMARY KEY,
    poke_name text NOT NULL,
    poke_type text NOT NULL,
    poke_desc text NOT NULL          
    )"""
    cursor.execute(poke_table_create)
    #I know theres more pokemon, but i dont want more than 550
    for x in range(1,551):
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
        poke_insert_logic = f'''INSERT INTO pokemon(poke_id, poke_name, poke_type, poke_desc) VAlUES("{x}", "{poke_name}", "{poke_type}", {poke_desc})'''
        #print(poke_insert_logic)
        cursor.execute(poke_insert_logic)
        
except sqlite3.Error as e: 
    print(e) 

finally:
    conn.commit() #your db will be empty without this
    conn.close()

