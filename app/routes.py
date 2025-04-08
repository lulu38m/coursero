from flask import render_template, redirect, url_for, flash, request, current_app
from app import app, db, bcrypt
from app.models import User
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import text
import os
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient

# Définir le dossier où les fichiers uploadés seront stockés localement
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        password = request.form.get('password')

        # Vérifier si l'adresse email est déjà utilisée
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Adresse email déjà enregistrée.', 'warning')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(fullname=fullname, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Compte créé avec succès. Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Connexion réussie.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email ou mot de passe invalide.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    flash('Déconnexion réussie.', 'success')
    return redirect(url_for('login'))


@app.route('/submission', methods=['GET'])
def submission():
    # Affiche uniquement le formulaire de dépôt de fichier
    return render_template('submission.html')


@app.route('/submit', methods=['POST'])
def submit_file():
    # Récupération des données du formulaire
    course = request.form.get('course')
    exercise = request.form.get('exercise')
    language = request.form.get('language')
    file = request.files.get('file')

    if not file:
        flash("Aucun fichier sélectionné.", "danger")
        return redirect(url_for('submission'))

    # Utiliser directement le nom du fichier tel quel
    filename = file.filename
    local_file_path = os.path.join(UPLOAD_FOLDER, filename)

    # Enregistrer le fichier en local
    file.save(local_file_path)
    flash("Fichier enregistré localement.", "info")

    # Définir le chemin cible sur la VM de correction (par exemple, dans /tmp/)
    remote_file_path = f"/tmp/{filename}"

    # Appeler la fonction qui enverra le fichier via SCP
    try:
        send_file_scp(local_file_path, remote_file_path)
        flash("Fichier envoyé à la VM de correction.", "success")
    except Exception as e:
        flash(f"Erreur lors de l'envoi du fichier: {e}", "danger")

    # Ici, ajoutez la logique pour enregistrer la soumission dans la base de données si nécessaire
    return redirect(url_for('index'))


@app.route('/results')
def results():
    # Logique spécifique pour afficher les résultats des corrections
    return render_template('results.html')


def send_file_scp(local_file_path, remote_file_path):
    """
    Envoie le fichier spécifié par local_file_path à la VM de correction
    via SCP, en le sauvegardant à l'emplacement remote_file_path sur la VM.

    Modifiez les paramètres de connexion SSH ci-dessous en fonction de votre environnement.
    """
    # Paramètres de connexion à la VM de correction
    hostname = '172.16.77.159'  # Remplacez par l'IP ou le nom d'hôte de la VM de correction
    port = 22  # Port SSH (généralement 22)
    username = 'admincorrection'  # Nom d'utilisateur pour la connexion SSH
    password = 'Password'  # Mot de passe pour la connexion SSH

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(hostname, port=port, username=username, password=password)

    with SCPClient(ssh.get_transport()) as scp:
        scp.put(local_file_path, remote_file_path)

    ssh.close()
