FROM python:3.11-slim
WORKDIR /app
COPY scanner-core/ ./scanner-core/
RUN pip install -e ./scanner-core --quiet
COPY scanners/xss/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt --quiet
COPY scanners/xss/ ./
CMD ["python", "main.py"]
