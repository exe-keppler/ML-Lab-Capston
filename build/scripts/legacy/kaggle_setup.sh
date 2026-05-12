#!/usr/bin/env bash
# Diagnóstico legacy: instala kaggle CLI en venv y configura credenciales.
# Las credenciales se leen de variables de entorno (NO hardcodear acá).
# Uso:
#   KAGGLE_USERNAME=mi_user KAGGLE_KEY=mi_key sudo -E bash kaggle_setup.sh
#
# Obtener el token en https://www.kaggle.com/settings → "Create New API Token".
# El JSON descargado tiene la forma {"username":"...","key":"..."}.

set +e
PROJ=/home/operador/Laboratorio-MLCyber
sec() { echo; echo "===== $* ====="; }

: "${KAGGLE_USERNAME:?Set KAGGLE_USERNAME (export o inline)}"
: "${KAGGLE_KEY:?Set KAGGLE_KEY (https://www.kaggle.com/settings → API → Create New Token)}"

sec "1. Python / pip disponible"
python3 --version
python3 -m pip --version 2>&1 | head -2

sec "2. Crear venv y instalar kaggle + pandas + pyarrow"
# Ubuntu 24.04 usa PEP 668 - necesito venv o --break-system-packages
VENV=/home/operador/kaggle_env
if [ ! -d "$VENV" ]; then
  apt-get install -y python3-venv python3-pip >/dev/null 2>&1
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade pip kaggle pandas pyarrow numpy 2>&1 | tail -3
echo '-- version kaggle --'
"$VENV/bin/kaggle" --version 2>&1 | head -3

sec "3. Configurar credenciales Kaggle desde env vars"
mkdir -p /home/operador/.kaggle
cat > /home/operador/.kaggle/kaggle.json <<EOF
{"username":"$KAGGLE_USERNAME","key":"$KAGGLE_KEY"}
EOF
chmod 600 /home/operador/.kaggle/kaggle.json
chown -R operador:operador /home/operador/.kaggle

sec "4. Test auth"
sudo -u operador bash -c '
export KAGGLE_CONFIG_DIR=/home/operador/.kaggle
'"$VENV"'/bin/kaggle datasets list -s cicids2017 --max-size 2147483648 2>&1 | head -15
' 2>&1 | head -15

sec "5. Metadata de dhoogla/cicids2017"
sudo -u operador bash -c "export KAGGLE_CONFIG_DIR=/home/operador/.kaggle; $VENV/bin/kaggle datasets metadata dhoogla/cicids2017 -p /tmp 2>&1" | head -5
ls -la /tmp/dataset-metadata.json 2>&1

echo; echo "===== FIN setup auth ====="
