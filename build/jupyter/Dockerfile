FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Stack pedagógico que cubre los 8 notebooks del lab:
#  - jupyterlab + nbconvert: ejecutar notebooks en UI o CLI.
#  - sklearn + xgboost: modelos (RF v2 + XGBoost v2 tuneados).
#  - statsmodels: VIF iterativo del notebook 03 (feature audit).
#  - adversarial-robustness-toolbox: HopSkipJump del notebook 07.
#  - pandas/numpy/matplotlib/seaborn/pyarrow: data + viz.
RUN pip install --no-cache-dir \
        jupyterlab \
        nbconvert \
        scikit-learn \
        "xgboost>=2.0.0" \
        statsmodels \
        adversarial-robustness-toolbox \
        pandas \
        numpy \
        matplotlib \
        seaborn \
        joblib \
        requests \
        pyarrow

RUN groupadd -r -g 1000 app && useradd -r -u 1000 -g app -m -d /home/app -s /bin/bash app
USER app
WORKDIR /home/app
EXPOSE 8888
CMD ["sh", "-c", "jupyter lab --ip=0.0.0.0 --port=8888 --no-browser --IdentityProvider.token=\"${JUPYTER_TOKEN}\" --ServerApp.allow_origin='*' --ServerApp.disable_check_xsrf=True"]
