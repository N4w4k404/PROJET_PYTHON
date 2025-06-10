from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Initialisation de la base de données (avec vulnérabilités)
def init_db():
    conn = sqlite3.connect("vulnerable.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', '1234'), ('user', 'password')")
    conn.commit()
    conn.close()

init_db()  # Création de la base de données si elle n'existe pas

# Nouvelle route pour la page d'accueil/menu
@app.route("/")
def index():
    return '''
        <h1>Bienvenue sur l'application vulnérable !</h1>
        <p>Choisissez une action :</p>
        <ul>
            <li><a href="http://127.0.0.1:5000/login">Se connecter (vulnérable à l'injection SQL)</a></li>
            <li><a href="http://127.0.0.1:5000/comment">Laisser un commentaire (vulnérable à XSS)</a></li>
        </ul>
    '''



# Route vulnérable à l'injection SQL
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("vulnerable.db")
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"Executing query: {query}")  # Affichage pour voir l'injection SQL possible
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return f"Bienvenue, {user[1]} !"
        else:
            return "Échec de connexion."

    return '''
        <form method="post">
            Nom d'utilisateur : <input type="text" name="username"><br>
            Mot de passe : <input type="password" name="password"><br>
            <input type="submit" value="Se connecter">
        </form>
    '''

# Route vulnérable à XSS
@app.route("/comment", methods=["GET", "POST"])
def comment():
    if request.method == "POST":
        user_comment = request.form["comment"]
        return f"Commentaire reçu : {user_comment}"

    return '''
        <form method="post">
            Entrez votre commentaire : <input type="text" name="comment"><br>
            <input type="submit" value="Envoyer">
        </form>
    '''

if __name__ == "__main__":
    app.run(debug=True)