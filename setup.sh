sudo mkdir -p /opt/Hscripts/QHive/
sudo cp ./qhive.py /opt/Hscripts/QHive/
sudo cp ./qhive.conf /opt/Hscripts/QHive/
sudo cp ./qhive.service /etc/systemd/system/
sudo mkdir -p /opt/Hscripts/conf
sudo systemctl enable qhive
