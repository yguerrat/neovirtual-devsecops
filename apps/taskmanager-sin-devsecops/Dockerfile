# Imagen "como se hacía antes": base antigua, corre como root, modo debug activo.
FROM python:3.9

WORKDIR /app
COPY . .

RUN pip install -r requirements.txt && python create_db.py

ENV FLASK_APP=app.py \
    FLASK_DEBUG=1

EXPOSE 5000
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
