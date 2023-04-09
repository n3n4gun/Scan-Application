import nmap3
import networkscan
import datetime
import pythonping
import re
import socket
import json
import threading

from StylesPyQt import *
from PySide6 import QtCore, QtWidgets
from PySide6.QtWidgets import QMessageBox

class scanner_application(object):
    def setupUi(self, MainWindow):

        # данные строчки отвечают просто за то, чтобы определить текущий ipv4 адрес устройства, на котором запускается приложение
        self.sct = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sct.connect(('8.8.8.8', 1))

        self.ip = self.sct.getsockname()[0]

        MainWindow.setObjectName("MainWindow")
        MainWindow.setEnabled(True)
        MainWindow.resize(550, 300)

        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser.setGeometry(QtCore.QRect(10, 40, 371, 261))
        self.textBrowser.setObjectName("textBrowser")

        self.textBrowser.setStyleSheet(
            TextBrowserStyle
        )

        # поле ввода IP адреса сети
        self.IpField = QtWidgets.QLineEdit(self.centralwidget)
        self.IpField.setGeometry(QtCore.QRect(10, 10, 161, 20))
        self.IpField.setObjectName("IpField")
        self.IpField.setPlaceholderText('IP-адрес сети или устройства')

        # при помощи данной конструкции можно задавать CSS-стили для элементов приложения, импортирую из файла StylesPyQt.py
        self.IpField.setStyleSheet(
            IpFieldStyle
        )

        self.getIPs = QtWidgets.QPushButton(self.centralwidget)
        self.getIPs.setGeometry(QtCore.QRect(400, 120, 121, 31))
        self.getIPs.setObjectName("pushButton")

        self.pingAddr = QtWidgets.QPushButton(self.centralwidget)
        self.pingAddr.setGeometry(QtCore.QRect(400, 160, 121, 31))
        self.pingAddr.setObjectName("pushButton_2")

        self.scanButton = QtWidgets.QPushButton(self.centralwidget)
        self.scanButton.setGeometry(QtCore.QRect(400, 200, 121, 31))
        self.scanButton.setObjectName("pushButton_3")

        self.exitButton = QtWidgets.QPushButton(self.centralwidget)
        self.exitButton.setGeometry(QtCore.QRect(400, 240, 121, 31))
        self.exitButton.setObjectName("pushButton_4")

        # поле ввода маски сети
        self.MaskField = QtWidgets.QLineEdit(self.centralwidget)
        self.MaskField.setGeometry(QtCore.QRect(180, 10, 90, 20))
        self.MaskField.setObjectName("MaskField")
        self.MaskField.setPlaceholderText('Формат маски')

        self.MaskField.setStyleSheet(
            MaskFieldStyle
        )

        self.cleanButton = QtWidgets.QPushButton(self.centralwidget)
        self.cleanButton.setGeometry(QtCore.QRect(280, 10, 101, 21))
        self.cleanButton.setObjectName("pushButton_5")

        self.comboBox = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(400, 10, 121, 22))
        self.comboBox.setObjectName("comboBox")

        types_of_scanning = [
            'TCP', 
            'UDP', 
            'SYN', 
            'Scan Top ports', 
            'OS detection', 
            'IDLE scan',
            'Surface Scanning'
            ]

        self.comboBox.addItems(types_of_scanning)

        self.comboBox.setStyleSheet(
            ComboBoxStyle
        )

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 550, 18))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)

        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", f'Адрес устройства: {self.ip}'))

        self.getIPs.setText(_translate("MainWindow", "Получение адресов"))
        self.getIPs.clicked.connect(self.getLocalIps)

        self.pingAddr.setText(_translate("MainWindow", "Пинг адреса"))
        self.pingAddr.clicked.connect(self.pingIpAddr)

        self.scanButton.setText(_translate("MainWindow", "Сканирование"))
        self.scanButton.clicked.connect(self.scanningMethods)

        self.exitButton.setText(_translate("MainWindow", "Выход"))
        self.exitButton.clicked.connect(self.exitApp)

        self.cleanButton.setText(_translate("MainWindow", "Очистить"))
        self.cleanButton.clicked.connect(self.cleanLineEdit)

    # выход из приложения
    def exitApp(self):
        self.warningMessage = QMessageBox.question(MainWindow, 'Предупреждение', 'Вы точно хотите выйти из приложения?', QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No)
        if self.warningMessage == QMessageBox.StandardButton.Yes:
            MainWindow.close()

    # очищение полей для ввода
    def cleanLineEdit(self):
        self.IpField.setText('');
        self.MaskField.setText('')

    # получение адресов в локальной сети
    # для того, чтобы получить список ip-адресов, входящих в локальную сеть необходимо указать формат сети, которую необходимо просканировать на наличие устройств
    # например у нас имеется локальная сеть, основной шлюз которой имеет адрес 10.19.15.1, таким образом, чтобы получить адреса, находящиеся в данной сети, необходимо указать следующий формат сети 10.19.15.0
    # также необходимо указать маску сети

    def getLocalIps(self):
        self.IpAddr = self.IpField.text()
        self.NetMask = self.MaskField.text()

        self.IpRegex = r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'

        if self.IpAddr == '':
            QMessageBox.warning(MainWindow, 'Предупреждение!', 'Необходимо указать IP-адрес!', QMessageBox.StandardButton.Ok)
            self.IpField.setFocus()
            
        elif self.NetMask == '':
            QMessageBox.warning(MainWindow, 'Предупреждение!', 'Необходимо указать формат маски сети!', QMessageBox.StandardButton.Ok)
            self.MaskField.setFocus()

        else:
            if re.fullmatch(self.IpRegex, self.IpAddr) and int(self.NetMask) <= 32:

                self.NetworkFormat = '{}/{}'.format(self.IpAddr, self.NetMask)
                self.NetScan = networkscan.Networkscan(self.NetworkFormat)

                self.NetScan.run()

                for self.addresses in self.NetScan.list_of_hosts_found:
                    self.textBrowser.append('[+] {}'.format(self.addresses))

                self.textBrowser.append('Number of hosts found: {}'.format(self.NetScan.nbr_host_found))

                self.time = datetime.datetime.now()
                self.textBrowser.append('-------------------{}.{}.{} {}:{}---------------------------\n'.format(self.time.day, self.time.month, self.time.year, self.time.hour, self.time.minute))

            else:
                QMessageBox.warning(MainWindow, 'Предупрждение', 'Проверте корректность указаного IP-адреса и формата маски сети!', QMessageBox.StandardButton.Ok)

    # Пинг IP-адреса
    def pingIpAddr(self):
        self.IpAddr = self.IpField.text()
        self.IpRegex = r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'

        if self.IpAddr == '':
            QMessageBox.warning(MainWindow, 'Предупреждение!', 'Необходимо указать IP-адрес!', QMessageBox.StandardButton.Ok)
            self.IpField.setFocus()

        else:
            if re.fullmatch(self.IpRegex, self.IpAddr):
                self.textBrowser.append('{}'.format(pythonping.ping(self.IpAddr)))

                self.time = datetime.datetime.now()
                self.textBrowser.append('-------------------{}.{}.{} {}:{}---------------------------\n'.format(self.time.day, self.time.month, self.time.year, self.time.hour, self.time.minute))

            else:
                QMessageBox.warning(MainWindow, 'Предупрждение', 'Проверте корректность указаного IP-адреса!', QMessageBox.StandardButton.Ok)
                self.IpField.setFocus()

    # выбор метода и процесс сканирования
    def scanningMethods(self):
        self.IpAddr = self.IpField.text()
        self.scanType = str(self.comboBox.currentText())
        self.IpRegex = r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'

        if self.IpAddr != '':
            if re.fullmatch(self.IpRegex, self.IpAddr):
                if self.scanType == 'TCP':
                    try:
                        self.tcpNmap = nmap3.NmapScanTechniques()

                        for self.TCPscanInformation in self.tcpNmap.nmap_tcp_scan(self.IpAddr)[self.IpAddr]['ports']:
                            self.textBrowser.append('Protocol: {} | PortId: {} | State: {} | Service: {}'.format(self.TCPscanInformation['protocol'], self.TCPscanInformation['portid'], self.TCPscanInformation['state'], self.TCPscanInformation['service']['name']))

                        self.time = datetime.datetime.now()
                        self.textBrowser.append('-------------------{}.{}.{} {}:{}---------------------------\n'.format(self.time.day, self.time.month, self.time.year, self.time.hour, self.time.minute))
                    
                    except KeyError:
                        pass

                elif self.scanType == 'UDP':
                    try:
                        self.udpNmap = nmap3.NmapScanTechniques()

                        for self.UDPscanInformation in self.udpNmap.nmap_udp_scan(self.IpAddr)[self.IpAddr]['ports']:
                            self.textBrowser.append('Protocol: {} | PortId: {} | State: {} | Service: {}'.format(self.UDPscanInformation['protocol'], self.UDPscanInformation['portid'], self.UDPscanInformation['state'], self.UDPscanInformation['service']['name']))

                        self.time = datetime.datetime.now()
                        self.textBrowser.append('-------------------{}.{}.{} {}:{}---------------------------\n'.format(self.time.day, self.time.month, self.time.year, self.time.hour, self.time.minute))

                    except:
                        QMessageBox.warning(MainWindow, 'Предупреждение', 'Для выполнения данной функции необходимы права администратора!', QMessageBox.StandardButton.Ok)

                elif self.scanType == 'SYN':
                    try:
                        self.synNmap = nmap3.NmapScanTechniques()

                        for self.SYNscanInformtion in self.synNmap.nmap_syn_scan(self.IpAddr)[self.IpAddr]['ports']:
                            self.textBrowser.append('Protocol: {} | PortId: {} | State: {} | Service: {}'.format(self.SYNscanInformtion['protocol'], self.SYNscanInformtion['portid'], self.SYNscanInformtion['state'], self.SYNscanInformtion['service']['name']))

                        self.time = datetime.datetime.now()
                        self.textBrowser.append('-------------------{}.{}.{} {}:{}---------------------------\n'.format(self.time.day, self.time.month, self.time.year, self.time.hour, self.time.minute))
            
                    except:
                        QMessageBox.warning(MainWindow, 'Предупреждение', 'Для выполнения данной функции необходимы права администратора!', QMessageBox.StandardButton.Ok)

                elif self.scanType == 'Scan Top ports':
                    self.stpNmap = nmap3.Nmap()
                    
                    for self.STPscanInformation in self.stpNmap.scan_top_ports(self.IpAddr)[self.IpAddr]['ports']:
                        self.textBrowser.append('Protocol: {} | PortId: {} | State: {} | Service: {}'.format(self.STPscanInformation['protocol'], self.STPscanInformation['portid'], self.STPscanInformation['state'], self.STPscanInformation['service']['name']))

                    self.time = datetime.datetime.now()
                    self.textBrowser.append('-------------------{}.{}.{} {}:{}---------------------------\n'.format(self.time.day, self.time.month, self.time.year, self.time.hour, self.time.minute))

                elif self.scanType == 'OS detection':

                    self.osNmap = nmap3.Nmap()
                    self.os_information = self.osNmap.nmap_os_detection(self.IpAddr)

                    if self.os_information != {'error': True, 'msg': 'You must be root/administrator to continue!'}:
                        try:
                            self.textBrowser.append('[+] Device address: {} | OS: {} | Hostname: {}'.format(self.IpAddr, self.os_information[self.IpAddr]['osmatch'][0]['name'], self.os_information[self.IpAddr]['hostname'][0]['name']))
                            self.time = datetime.datetime.now()
                            self.textBrowser.append('-------------------{}.{}.{} {}:{}---------------------------\n'.format(self.time.day, self.time.month, self.time.year, self.time.hour, self.time.minute))
                        
                        except KeyError:
                            self.textBrowser.append('[+] Не удалось идентифицировать ОС устройства!')
                        
                            self.time = datetime.datetime.now()
                            self.textBrowser.append('-------------------{}.{}.{} {}:{}---------------------------\n'.format(self.time.day, self.time.month, self.time.year, self.time.hour, self.time.minute))
                            
                    else:
                        QMessageBox.warning(MainWindow, 'Предупреждение', 'Для выполнения данной функции необходимы права администратора!', QMessageBox.StandardButton.Ok)

                elif self.scanType == 'IDLE scan':
                    self.device = nmap3.NmapScanTechniques()

                    self.device_type = self.device.nmap_idle_scan(self.IpAddr)

                    if self.device_type[self.IpAddr]['hostname'] != []:

                        self.textBrowser.append('[+] Device address: {} | Hostname: {} | State: {} | Info: {}'.format(self.IpAddr, self.device_type[self.IpAddr]['hostname'][0]['name'], self.device_type[self.IpAddr]['state']['state'], self.device_type['runtime']['summary']))

                        self.time = datetime.datetime.now()
                        self.textBrowser.append('-------------------{}.{}.{} {}:{}---------------------------\n'.format(self.time.day, self.time.month, self.time.year, self.time.hour, self.time.minute))
                    
                    else:

                        self.textBrowser.append('[+] Не удалось идентифицировать устройство!')
                        self.time = datetime.datetime.now()
                        self.textBrowser.append('-------------------{}.{}.{} {}:{}---------------------------\n'.format(self.time.day, self.time.month, self.time.year, self.time.hour, self.time.minute))

                elif self.scanType == 'Surface Scanning':
                    
                    def surface_port_scan(ip_V4, port_id):
                        connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                        try:
                            connection_socket.connect((ip_V4, port_id))

                        except:
                            self.textBrowser.append(f'[+] Connetction with {ip_V4}:{port_id} is failed')

                        else:
                            self.textBrowser.append(f'[+] Device address: {ip_V4} | PortId: {port_id} | Service: {ports_json[str(port_id)]}')

                            connection_socket.close()

                    with open('ports.json', 'r') as ports_file:
                        ports_json = json.load(ports_file)

                    ip_V4 = self.IpAddr

                    for port_id in ports_json:
                        scan_thread = threading.Thread(target = surface_port_scan, args = (ip_V4, int(port_id), ))
                        scan_thread.start()

            else:
                QMessageBox.warning(MainWindow, 'Предупреждение', 'Проверьте корректность указанного IP-адреса!', QMessageBox.StandardButton.Ok)
                self.IpField.setFocus()

        else:
            QMessageBox.warning(MainWindow, 'Предупреждение', 'Введети IP-адрес для сканирования!', QMessageBox.StandardButton.Ok)
            self.IpField.setFocus()

if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = scanner_application()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
