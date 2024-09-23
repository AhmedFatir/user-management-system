FROM debian:bullseye

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y \
netcat vim nginx zsh curl httpie wget git iputils-ping \
procps apt-utils net-tools tree jq man \
python3 python3-pip python3-venv \
postgresql-client npm nodejs \
&& apt-get clean

# Set zsh as the default shell
RUN chsh -s $(which zsh)

# Install Oh My Zsh for a better shell experience
RUN wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh
RUN chmod +x install.sh && yes | ./install.sh
RUN rm install.sh && mkdir /root/lab

COPY ./zshrc /root/.zshrc
COPY ./zsh_history /root/.zsh_history
COPY ./lab /root/lab

# RUN pip install --no-cache-dir -r /root/lab/requirements.txt

CMD ["tail", "-f", "/dev/null"]
