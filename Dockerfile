# Utiliser une image de base Python

FROM python:3.13-slim

# Creer un utilisateur non-root et son groupe

RUN addgroup --system appgroup && adduser --system --group appuser

# Définir le répertoire de travail dans le conteneur

WORKDIR /app

# Copier les fichiers dans le conteneur

COPY requirements.txt requirements.txt

COPY app.py app.py

COPY private_key.pem private_key.pem

COPY controller.py controller.py

COPY utils.py utils.py

# COPY . .

 

# Installer les dépendances

RUN pip install -r requirements.txt

# Changer la propriete des fichiers au nouvel utilisateur non root

RUN chown -R appuser:appgroup /app

# Changer l'utilisateur actif pour le nouvel utilisateur non root

USER appuser

# Exposer le port pour Flask

# EXPOSE 443
# EXPOSE $PORT

# Set environment variable for Flask to run in production mode

ENV FLASK_ENV=production

ENV PYTHONUNBUFFERED=1

# Démarrer l'application avec Gunicorn

CMD ["sh", "-c", "gunicorn app:app -b 0.0.0.0:${PORT} --log-level debug"]