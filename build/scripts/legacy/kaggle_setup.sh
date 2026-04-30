#!/usr/bin/env bash
set +e
PROJ=/home/operador/Laboratorio-MLCyber
sec() { echo; echo "===== $* ====="; }

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

sec "3. Configurar credenciales Kaggle (probando SIN prefijo KGAT_)"
mkdir -p /home/operador/.kaggle
cat > /home/operador/.kaggle/kaggle.json <<EOF
{"username":"Netd1e","key":"49d3e45c0e8f84fd17cc924d50f3da8b"}
EOF
chmod 600 /home/operador/.kaggle/kaggle.json
chown -R operador:operador /home/operador/.kaggle

sec "4. Test auth - variante 1: key sin KGAT_"
sudo -u operador bash -c '
export KAGGLE_CONFIG_DIR=/home/operador/.kaggle
'"$VENV"'/bin/kaggle datasets list -s cicids2017 --max-size 2147483648 2>&1 | head -15
' 2>&1 | head -15

sec "5. Si 403, probar CON prefijo KGAT_"
if sudo -u operador bash -c 'export KAGGLE_CONFIG_DIR=/home/operador/.kaggle; '"$VENV"'/bin/kaggle datasets list -s cicids2017 2>&1 | grep -q "401\|403\|Invalid"'; then
  echo "-> Probando con KGAT_49d3e45c0e8f84fd17cc924d50f3da8b"
  cat > /home/operador/.kaggle/kaggle.json <<EOF
{"username":"Netd1e","key":"KGAT_49d3e45c0e8f84fd17cc924d50f3da8b"}
EOF
  chmod 600 /home/operador/.kaggle/kaggle.json
  chown -R operador:operador /home/operador/.kaggle
  sudo -u operador bash -c 'export KAGGLE_CONFIG_DIR=/home/operador/.kaggle; '"$VENV"'/bin/kaggle datasets list -s cicids2017 2>&1 | head -10'
fi

sec "6. Ruta final - tamano de dhoogla/cicids2017"
sudo -u operador bash -c "export KAGGLE_CONFIG_DIR=/home/operador/.kaggle; $VENV/bin/kaggle datasets metadata dhoogla/cicids2017 -p /tmp 2>&1" | head -5
ls -la /tmp/dataset-metadata.json 2>&1

echo; echo "===== FIN setup auth ====="
