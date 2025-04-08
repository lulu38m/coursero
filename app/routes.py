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
    remote_directory = "/etc/coursero/"
    # On transmet directement le répertoire de destination
    # Le fichier sera placé sous remote_directory + filename
    if send_file_scp(local_file_path, remote_directory):
        flash("Fichier envoyé à la VM de correction.", "success")
    else:
        flash("Erreur lors de l'envoi du fichier.", "danger")

    # Ici, ajoutez la logique pour enregistrer la soumission dans la base de données si nécessaire

    return redirect(url_for('index'))


@app.route('/results')
def results():
    # Logique spécifique pour afficher les résultats des corrections
    return render_template('results.html')


def send_file_scp(local_file_path, remote_directory):
    try:
        ssh = SSHClient()
        ssh.load_system_host_keys()
        ssh.connect(
            hostname='172.16.77.159',
            port=22,
            username='admincorrection',
            password='Password'
        )

        scp = SCPClient(ssh.get_transport())
        remote_file_path = os.path.join(remote_directory, os.path.basename(local_file_path))
        scp.put(local_file_path, remote_file_path)
        scp.close()
        ssh.close()
        return True
    except Exception as e:
        print(f"Erreur SCP: {e}")
        return False

