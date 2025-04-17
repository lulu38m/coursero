from flask import render_template, redirect, url_for, flash, request, current_app, jsonify
from app import app, db, bcrypt
from app.models import User
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import text
import os
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient
from app.models import Submission
from datetime import datetime


API_TOKEN = os.environ.get('CORRECTION_API_TOKEN', 'yX9vT3kLmQ8pR1sZ')

# Définir le dossier où les fichiers uploadés seront stockés localement
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

REMOTE_DIRECTORY = '/etc/coursero'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/result', methods=['POST'])
def receive_result():
    # Vérification du token
    token = request.headers.get('X-Auth-Token')
    if token != API_TOKEN:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(force=True)
    sub_id = data.get('submission_id')
    score  = data.get('score')

    if sub_id is None or score is None:
        return jsonify({'error': 'Bad request'}), 400

    submission = Submission.query.get(sub_id)
    if not submission:
        return jsonify({'error': 'Submission not found'}), 404

    submission.score = int(score)
    submission.submission_date = datetime.utcnow()
    db.session.commit()

    return jsonify({'status': 'ok'}), 200


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
    course = request.form.get('course')
    exercise = request.form.get('exercise')
    language = request.form.get('language')
    file = request.files.get('file')

    if not file:
        flash("Aucun fichier sélectionné.", "danger")
        return redirect(url_for('submission'))

    filename = file.filename
    local_file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(local_file_path)

    # Créez d’abord l’entrée pour obtenir l’ID
    new_submission = Submission(
        course=course,
        exercise=exercise,
        language=language,
        filename=''  # temporaire
    )
    db.session.add(new_submission)
    db.session.commit()

    # Renommez le fichier local pour inclure l'ID
    submission_id = new_submission.id
    new_filename = f"{submission_id}_{filename}"
    new_path = os.path.join(UPLOAD_FOLDER, new_filename)
    os.rename(local_file_path, new_path)

    # Mettez à jour l’objet Submission
    new_submission.filename = new_filename
    db.session.commit()

    # Envoi en SCP
    if send_file_scp(new_path, REMOTE_DIRECTORY):
        flash("Fichier envoyé à la VM de correction.", "success")
    else:
        flash("Erreur lors de l'envoi du fichier.", "danger")

    flash("Soumission enregistrée avec succès.", "success")
    return redirect(url_for('index'))


@app.route('/results')
def results():
    submissions = Submission.query.all()
    return render_template('results.html', submissions=submissions)


def send_file_scp(local_file_path, remote_directory):
    try:
        ssh = SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

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


