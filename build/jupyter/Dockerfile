FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir jupyterlab scikit-learn pandas numpy matplotlib seaborn joblib requests adversarial-robustness-toolbox pyarrow nbconvert
RUN groupadd -r -g 1000 app && useradd -r -u 1000 -g app -m -d /home/app -s /bin/bash app
USER app
WORKDIR /home/app
EXPOSE 8888
CMD ["sh", "-c", "jupyter lab --ip=0.0.0.0 --port=8888 --no-browser --IdentityProvider.token=\"${JUPYTER_TOKEN}\" --ServerApp.allow_origin='*' --ServerApp.disable_check_xsrf=True"]
