#!/bin/bash

cat > /root/.bashrc <<EOL
alias bashup='source ~/.bashrc'
alias ..='cd ..'
alias rmf='rm -rf'
alias py='python3.9'
alias pym='python3.9 manage.py'
alias pymm='python3.9 manage.py makemigrations && python3.9 manage.py migrate'
alias pymr='python3.9 manage.py runserver'
alias pymt='python3.9 manage.py test --verbosity 2'
alias pyma='python3.9 manage.py createsuperuser --username admin --email admin@email.com'
alias pipi='pip install -r requirements.txt'
alias pipf='pip freeze > requirements.txt'
EOL

python manage.py makemigrations
python manage.py migrate
python manage.py runserver 0.0.0.0:8000