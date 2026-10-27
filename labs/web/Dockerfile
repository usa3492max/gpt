# A single-file, deliberately vulnerable web app for exercising redloop.
FROM python:3.12-slim

LABEL description="redloop practice target — intentionally vulnerable, never expose publicly"

WORKDIR /lab
COPY lab.py .

ENV LAB_BIND=0.0.0.0 \
    PORT=8080 \
    PYTHONUNBUFFERED=1 \
    FLAG=flag{r3dl00p_l4b_sql1_byp4ss}

EXPOSE 8080

# Unbuffered, no healthcheck dependencies, no shell wrapper.
CMD ["python", "-u", "lab.py"]
