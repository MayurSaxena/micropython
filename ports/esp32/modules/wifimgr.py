import network
import socket
import ure
import time
import urequests as requests

# base code from https://github.com/tayfunulu/WiFiManager/

class WiFiManager:
    def __init__(self, ap_ssid="WiFiMgr", ap_password="wifimanager!", storage_location="wifi.dat"):
        self.__ap_ssid = ap_ssid # Name of the WiFi AP
        self.__ap_password = ap_password # Password of the WiFi AP
        self.__storage_location = storage_location # Where to store WiFi credentials
        self.__wlan_ap = network.WLAN(network.AP_IF) # The AP interface
        self.__wlan_sta = network.WLAN(network.STA_IF) # The client interface

    def ensure_connection(self):
        """Return WLAN STA instance if connected else None. Blocking function."""

        # Check to see if we're already connected
        if self.__wlan_sta.isconnected():
            return self.__wlan_sta

        connected = False
        try:
            # Read the profiles that have been saved before
            profiles = self.read_profiles()

            # Activate the client interface and scan which WiFi networks we see
            self.__wlan_sta.active(True)
            networks = self.__wlan_sta.scan()

            AUTHMODE = {0: "open", 1: "WEP", 2: "WPA-PSK", 3: "WPA2-PSK", 4: "WPA/WPA2-PSK"}
            for ssid, bssid, channel, rssi, authmode, hidden in sorted(networks, key=lambda x: x[3], reverse=True):
                ssid = ssid.decode('utf-8')
                encrypted = authmode > 0
                print("SSID: {0} Channel: {1} RSSI: {2} Authmode: {3}".format(ssid, channel, rssi, AUTHMODE.get(authmode, '?')))
                
                # if we have previously saved a seen network try connecting
                if ssid in profiles:
                    password = None if not encrypted else profiles[ssid]
                    connected = self.do_connect(ssid, password)
                    if connected:
                        return self.__wlan_sta

        except OSError as e: # this can occur if the profiles file doesn't exist yet
            print("Exception in WiFi Manager: {0}".format(str(e)))

        # start a web server and wait for the user to configure their wifi network
        connected = self.start_web_server() # will block until connected

        # tear it all down (at this point we should be connected - or something went wrong)
        self.stop_web_server()

        return self.__wlan_sta if connected else None
    
    def read_profiles(self):
        with open(self.__storage_location) as f:
            lines = f.readlines()
        profiles = {}
        for line in lines:
            ssid, password = line.strip("\n").split(";")
            profiles[ssid] = password
        return profiles

    def write_profiles(self, profiles):
        lines = []
        for ssid, password in profiles.items():
            lines.append("%s;%s\n" % (ssid, password))
        with open(self.__storage_location, "w") as f:
            f.write(''.join(lines))

    def do_connect(self, ssid, password):
        '''Return True/False if connection works.'''
        self.__wlan_sta.active(True) # STA interface should be acti
        if self.__wlan_sta.isconnected(): 
            return True
        print('Trying to connect to {0}...'.format(ssid))
        self.__wlan_sta.connect(ssid, password)
        for retry in range(100):
            connected = self.__wlan_sta.isconnected()
            if connected:
                print('\nConnection successful. Network config: ', self.__wlan_sta.ifconfig())
                return connected
            time.sleep(0.1)
            print('.', end='')

        print('\nFailed to connect to {0}.'.format(ssid))
        self.__wlan_sta.disconnect() # avoid the error where the interface is still trying to connect on next auth attempt
        self.__wlan_sta.active(False)
        self.__wlan_sta.active(True)
        return False

    def get_wifi_interface(self):
        return self.__wlan_sta

    def start_web_server(self):
        self.__wlan_sta.active(True) 
        self.__wlan_ap.active(True) # activate the WiFi AP with the auth parameters (3 is WPA2)
        self.__wlan_ap.config(essid=self.__ap_ssid, password=self.__ap_password, authmode=3)
        print("WiFi SSID {0} created. Password is {1}.".format(self.__ap_ssid, self.__ap_password))
        self.__ws = __MiniWebServer(self) # Start up a web server and block.
        self.__ws.initialize()
        self.__ws.listen_for_requests()

    def stop_web_server(self):
        self.__ws.shutdown() # Shutdown the web server and tear down the AP.
        self.__ws = None
        self.__wlan_ap.active(False)
        print('WiFi AP turned off.')

class __MiniWebServer:
    def __init__(self, wifimgr, port=80):
        self.manager = wifimgr
        self.__addr = socket.getaddrinfo('0.0.0.0', port)[0][-1]
        self.__port = port
        self.__socket = None

    def initialize(self):
        self.__socket = socket.socket()
        self.__socket.bind(self.__addr)
        self.__socket.listen(1)
        print('Web server listening on {0}'.format(self.__addr))
        print('Navigate to http://192.168.4.1:{0}'.format(self.__port))

    def listen_for_requests(self):
        while True: # block until connected
            if self.manager.get_wifi_interface().isconnected():
                return True
            client, addr = self.__socket.accept() # accept a connection
            print('Client connected from {0}.'.format(addr))
            try:
                client.settimeout(5.0)
                request = b""
                try:
                    while "\r\n\r\n" not in request:
                        request += client.recv(1024)
                except OSError:
                    pass

                if "HTTP" not in request:  # skip invalid requests
                    continue

                # version 1.9 compatibility
                try:
                    url = ure.search("(?:GET|POST) /(.*?)(?:\\?.*?)? HTTP", request).group(1).decode("utf-8").rstrip("/")
                except Exception:
                    url = ure.search("(?:GET|POST) /(.*?)(?:\\?.*?)? HTTP", request).group(1).rstrip("/")
                print("Desired URL is {0}".format('/' if url == '' else url))

                if url == "":
                    self.__handle_root(client)
                elif url == "configure":
                    self.__handle_configure(client, request)
                else:
                    self.__handle_not_found(client, url)
            finally:
                client.close()

    def __send_header(self, client, status_code=200, content_length=None ):
        client.sendall("HTTP/1.0 {} OK\r\n".format(status_code))
        client.sendall("Content-Type: text/html\r\n")
        if content_length is not None:
            client.sendall("Content-Length: {}\r\n".format(content_length))
        client.sendall("\r\n")

    def __send_response(self, client, payload, status_code=200):
        content_length = len(payload)
        self.__send_header(client, status_code, content_length)
        if content_length > 0:
            client.sendall(payload)
        client.close()

    def __handle_not_found(self, client, url):
        self.__send_response(client, "Path not found: {0}".format(url), status_code=404)
        return False
        
    def __handle_root(self, client):
        # List all the available WiFi networks to connect to
        ssids = sorted(ssid.decode('utf-8') for ssid, *_ in self.manager.get_wifi_interface().scan())
        self.__send_header(client)
        client.sendall("""\
            <html>
                <h1 style="color: #5e9ca0; text-align: center;">
                    <span style="color: #ff0000;">
                        Choose Your Wi-Fi Network!
                    </span>
                </h1>
                <form action="configure" method="post">
                    <table style="margin-left: auto; margin-right: auto;">
                        <tbody>
        """)
        while len(ssids):
            ssid = ssids.pop(0)
            client.sendall("""\
                            <tr>
                                <td colspan="2">
                                    <input type="radio" name="ssid" value="{0}" required/>{0}
                                </td>
                            </tr>
            """.format(ssid))
        client.sendall("""\
                            <tr>
                                <td>Password:</td>
                                <td><input name="password" type="text" /></td>
                            </tr>
                        </tbody>
                    </table>
                    <p style="text-align: center;">
                        <input type="submit" value="Submit" />
                    </p>
                </form>
            </html>
        """)
        client.close()

    def __handle_configure(self, client, request):
        match = ure.search("ssid=([^&]*)&password=(.*)", request)

        if match is None:
            self.__send_response(client, "Parameters not found", status_code=400)
            return False
        # version 1.9 compatibility
        try:
            ssid = match.group(1).decode("utf-8").replace("%3F", "?").replace("%21", "!")
            password = match.group(2).decode("utf-8").replace("%3F", "?").replace("%21", "!")
        except Exception:
            ssid = match.group(1).replace("%3F", "?").replace("%21", "!")
            password = match.group(2).replace("%3F", "?").replace("%21", "!")
 
        if len(ssid) == 0:
            self.__send_response(client, "SSID must be provided", status_code=400)
            return False

        if self.manager.do_connect(ssid, password):
            response = """\
                <html>
                    <center>
                        <br><br>
                        <h1 style="color: #5e9ca0; text-align: center;">
                            <span style="color: #ff0000;">
                                Successfully connected to WiFi network {0}.
                            </span>
                        </h1>
                        <br><br>
                        <h1 style="color: #5e9ca0; text-align: center;">
                            <span style="color: #ff0000;">
                                You may now close this window.
                            </span>
                        </h1>
                    </center>
                </html>
            """.format(ssid)
            self.__send_response(client, response)
            try:
                profiles = self.manager.read_profiles()
            except OSError:
                profiles = {}
            profiles[ssid] = password
            self.manager.write_profiles(profiles) # write the new profile to disk
            return True
        else:
            response = """\
                <html>
                    <center>
                        <h1 style="color: #5e9ca0; text-align: center;">
                            <span style="color: #ff0000;">
                                Could not connect to WiFi network {0}.
                            </span>
                        </h1>
                        <br><br>
                        <form>
                            <input type="button" value="Go back!" onclick="history.back()"></input>
                        </form>
                    </center>
                </html>
            """.format(ssid)
            self.__send_response(client, response)
            return False

    def shutdown(self):
        print('Web server shutting down...')
        if self.__socket:
            self.__socket.close()
            self.__socket = None

class ConnectedRequester:
    # A simple class that ensures there is a WiFi connection before making a request
    def __init__(self, wifimgr):
        self.__manager = wifimgr
    def request(self, method, url, data=None, json=None, headers={}):
        self.__manager.ensure_connection()
        return requests.request(method.upper(), url, data, json, headers)

