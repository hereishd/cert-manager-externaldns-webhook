# ==========================================================
# STAGE 1: Vulnerability Security Audit
# ==========================================================
FROM python:3.13.14-alpine3.24 AS audit
WORKDIR /scan

COPY requirements.txt .

RUN pip install --no-cache-dir pip-audit && \
    pip-audit -r requirements.txt

# ==========================================================
# STAGE 2: Build 
# ==========================================================
FROM python:3.13.14-alpine3.24 AS runtime
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/app.py app/utils.py .

EXPOSE 10250

USER 10001

CMD ["python", "app.py"]