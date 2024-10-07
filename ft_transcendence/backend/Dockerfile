FROM python:3.9

WORKDIR /back
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
USER root
RUN chmod +x MAKE_MIGRATIONS.sh

CMD [ "bash", "MAKE_MIGRATIONS.sh" ]