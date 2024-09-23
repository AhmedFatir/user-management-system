FROM debian:bullseye

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y \
netcat vim zsh curl wget git \
procps apt-utils tree man \
python3 python3-pip python3-venv \
&& apt-get clean

RUN chsh -s $(which zsh)
RUN wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh \
&& chmod +x install.sh && yes | ./install.sh && rm install.sh

COPY ./zshrc /root/.zshrc
COPY ./zsh_history /root/.zsh_history
COPY ./lab /root/lab

RUN pip install --no-cache-dir -r /root/lab/ft_transcendence/backend/requirements.txt

CMD ["tail", "-f", "/dev/null"]
