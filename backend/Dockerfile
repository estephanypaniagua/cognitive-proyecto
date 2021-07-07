FROM python:3.8-slim-buster

WORKDIR /app

COPY requerimientos.txt requerimientos.txt
RUN pip3 install -r requerimientos.txt

COPY . .

CMD [ "python3", "app.py"]