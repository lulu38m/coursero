from flask import render_template, redirect, url_for, flash, request
from app import app, db, bcrypt
from app.models import User
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import text

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


@app.route('/submission')
def submission():
    # enregistrer le fichier en local ( dans dossier uploads dossier uploads )
    # appeler la fonction send_file_scp
    return render_template('submission.html')

@app.route('/results')
def results():
    # Vous pouvez ajouter ici la logique spécifique à la page des résultats
    return render_template('results.html')

# fonction pour envoyer le fichier via SCP
def send_file_scp(local_file_path, remote_file_path):
    """
    # remote_file_path = "/tmp
    # Implémentez ici la logique pour envoyer le fichier via SCP
    # connection en ssh
    # ssh = SSHClient()
    # ssh.load_system_host_keys()
    # ssh.connect(hostname, port, username, password)
    # scp = SCPClient(ssh.get_transport()
    # scp.put(local_file_path, remote_file_path)
    # scp.close()
    """

    pass