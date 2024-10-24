FROM python:3.9

COPY ./backend /root/backend
WORKDIR /root/backend
RUN pip install -r requirements.txt
USER root
RUN chmod +x runserver.sh
CMD [ "bash", "runserver.sh" ]

# FROM debian:bullseye

# RUN apt-get update && apt-get upgrade -y

# RUN apt-get install -y \
# netcat vim zsh curl wget git \
# procps apt-utils tree man \
# python3 python3-pip python3-venv \
# && apt-get clean

# RUN chsh -s $(which zsh)
# RUN wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh \
# && chmod +x install.sh && yes | ./install.sh && rm install.sh

# COPY ./zshrc /root/.zshrc
# COPY ./user-managment-system /root/user-managment-system

# RUN pip install --no-cache-dir -r /root/user-managment-system/backend/requirements.txt

# WORKDIR /root/user-managment-system/backend

# RUN python3.9 manage.py makemigrations && python3.9 manage.py migrate && python3.9 manage.py runserver

# CMD ["tail", "-f", "/dev/null"]
