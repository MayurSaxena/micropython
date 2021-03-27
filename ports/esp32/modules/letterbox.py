from esp32 import NVS
from machine import unique_id
from wifimgr import WiFiManager, ConnectedRequester
from ubinascii import hexlify, a2b_base64, b2a_base64
from uos import urandom, remove as remove_file
from utime import time as timestamp
import urequests as requests
from ujson import loads
from uzlib import decompress as inflate
from ucryptolib import aes
from ursa import rsa_decrypt, generate_rsa_signature
from ntptime import settime
import uasyncio
import gc

class __LetterBoxWiFiManager(WiFiManager):
    # A specialized WiFi manager that displays text on the screen.
    def __init__(self, display_obj, font_obj, ap_ssid="LetterBox", ap_password="LetterBox", storage_location="wifi.dat"):
        super().__init__(ap_ssid, ap_password, storage_location)
        self.__display = display_obj
        self.__render_font = font_obj

    def __display_webserver_help(self):
        self.__display.clear()
        self.__display.draw_text(0, 0, 'LetterBox needs Internet!', self.__render_font, 65535)
        self.__display.draw_text(0, 36, 'Connect to this Wi-Fi:', self.__render_font, 65535)
        self.__display.draw_text(30, 72, self.__ap_ssid, self.__render_font, 65535)
        self.__display.draw_text(30, 108, 'Password: {0}'.format(self.__ap_password), self.__render_font, 65535)
        self.__display.draw_text(0, 144, 'Navigate to this URL:', self.__render_font, 65535)
        self.__display.draw_text(30, 180, 'http://192.168.4.1', self.__render_font, 65535)
        self.__display.draw_text(0, 216, 'Enter your WiFi password.', self.__render_font, 65535)

    def start_web_server(self):
        self.__display_webserver_help()
        super().start_web_server()

    def stop_web_server(self):
        self.__display.clear()
        super().stop_web_server()


class LetterBox:
    def __init__(self, display_obj, notifier_obj, lid_sensor_obj, font_obj, nvs_namespace='LBOX_CFG'):
        self.__namespace = NVS(nvs_namespace) # non-volatile storage
        self.__display = display_obj
        self.__render_font = font_obj
        self.__notifier = notifier_obj
        self.__lid_sensor = lid_sensor_obj
        self.__wifi_manager = __LetterBoxWiFiManager(display_obj=self.__display,
                                                    font_obj=self.__render_font,
                                                    ap_ssid="LetterBox",
                                                    ap_password='L3tterb0x!')
        self.__requester = ConnectedRequester(self.__wifi_manager)
        self.serial_number = None
        self.private_key = None

    def initialize(self):
        initial_config_done = None
        try:
            self.__store_keys() # write any new keys if given
            initial_config_done = self.__namespace.get_i32("config_done") # check if this var exists in NVS
        except OSError: #means config hasn't been done
            print("Initializing device...")
            self.__onboard_device() # onboard the device (register the public key)
            self.__display_no_letter_text() # tell user to go register on front-end
            self.__namespace.set_i32("config_done", 1) # don't come back here again
            self.__namespace.commit()
            print("Device initialized.")
        finally:
            initial_config_done = self.__namespace.get_i32("config_done") #should be done now
            
            if initial_config_done == 1:
                self.serial_number = bytearray(12) # store the serial number for easy access
                self.__namespace.get_blob("serial_number", self.serial_number)
                self.serial_number = self.serial_number.decode('utf-8')
                print("Serial number is {0}.".format(self.serial_number))

                self.private_key = bytearray(self.__namespace.get_i32("pri_key_len")) # and store the private key
                self.__namespace.get_blob("pri_key", self.private_key)
                self.private_key = self.private_key.decode('utf-8')
                print('Private key loaded.')               
                return True
            return False # shouldn't happen

    def __onboard_device(self):
        print("Onboarding device...")
        # Onboarding consists of registering your serial number and public key with the server
        status_code = 0
        attempt_serial = unique_id() # first serial to try is the MAC address
        pub_key = bytearray(self.__namespace.get_i32("pub_key_len"))
        self.__namespace.get_blob("pub_key", pub_key)
        pub_key_b64 = b2a_base64(pub_key).strip().decode('utf-8')
        serial_number = None
        while status_code != 200: # will keep generating new serials until one works
            serial_number = hexlify(attempt_serial).strip().decode('utf-8').upper()
            r = self.__requester.request('POST','https://letterbox.mayursaxena.com/.netlify/functions/onboard', json={'id': serial_number, 'pk': pub_key_b64})
            status_code = r.status_code
            print('{0}: {1}'.format(r.status_code, r.reason))
            attempt_serial = urandom(6)
            r.close()
        self.__namespace.set_blob('serial_number', serial_number) # store the serial that worked in NVS
        self.__namespace.commit()
        print("Device onboarded with serial {0}.".format(serial_number))

    async def poll_async(self):
        while True:
            try:
                gc.collect() # something about memory
                gc.threshold(gc.mem_free() // 4 + gc.mem_alloc())
                print("Polling for new image...")
                url = "https://letterbox.mayursaxena.com/.netlify/functions/waiting"
                r = self.__requester.request('POST', url, json={"id":self.serial_number, "content":1})
                if r.status_code != 200:
                    print('{0} {1}: {2}'.format(r.status_code, r.reason, r.text))
                else:
                    json_resp = r.json()
                    if 'content' in json_resp:
                        img_bytes = self.__decrypt_img(loads(a2b_base64(json_resp["content"]).strip().decode('utf-8')))
                        notify_task = uasyncio.create_task(self.__start_notifier()) # start spinning!
                        print('Waiting for lid to open...')
                        await self.__wait_for_lid('open') # "blocks" until lid opens
                        notify_task.cancel() # stop spinning
                        self.__display_image(img_bytes) # put the image on the screen
                        print('Waiting for lid to close...')
                        await self.__wait_for_lid('close') # "blocks" until lid closes
                        self.__acknowledge_image(json_resp["sha"]) # delete image off the server
                        self.__display.clear() # clear the display to avoid burn-in (necessary?)
                r.close()
                await uasyncio.sleep(30) # wait 30 seconds between each poll
            except Exception as e:
                print("Encountered error in poll: {0}".format(e))
    
    async def __wait_for_lid(self, state):
        state = state.lower()
        if state not in ('open', 'close'):
            return False
        p_last = 0 # need to have two consecutive readings in order to trigger
        LOWER_BOUND = 500 # any reading above this on the photoresistor we're assuming means the lid is off
        while True:
            p_now = self.__lid_sensor.read()
            if LOWER_BOUND <= p_last and LOWER_BOUND <= p_now and state == 'open':
                return True
            elif p_last < LOWER_BOUND and p_now < LOWER_BOUND and state == 'close':
                return True
            p_last = p_now
            await uasyncio.sleep(1) # wait one second between each reading

    async def __start_notifier(self):
        # Servo motors have frequencies of 50Hz, meaning they update every 20ms
        # Duty ranges from 20 - 120 ==> 0 deg to 180 deg
        self.__notifier.duty(70)
        try:
            curr_duty = self.__notifier.duty()
            # make an array from 70...20...120...70
            duties = [i for i in range(curr_duty, 20, -1)] + [i for i in range(20,120)] + [i for i in range(120,curr_duty,-1)]
            while True:
                for i in duties:
                    self.__notifier.duty(i)
                    await uasyncio.sleep(0.005) # sleep for 5ms
                await uasyncio.sleep(3) # 3 seconds between each sweep
        except uasyncio.CancelledError:
            print('Cancelling notifier...')
            raise
        finally:
            self.__notifier.duty(70) # reset the position to 90 degrees
            print('Notifier cancelled.')

    def __display_image(self, img_bytes):
        self.__display.clear() # clear the image and put out a new image
        self.__display.draw_image(bytes=img_bytes)
    
    def __acknowledge_image(self, file_hash):
        print('Acknowledging image...')
        #send a message of form hash;timestamp (probably doesn't need to be b64)
        to_send = {'id': self.serial_number, 'message': b2a_base64('{0};{1}'.format(file_hash,timestamp())).strip().decode('utf-8')}
        signature = generate_rsa_signature(to_send['message'], self.private_key)
        to_send['signature'] = b2a_base64(signature).strip().decode('utf-8')
        # sign a message saying we've seen the image
        r = self.__requester.request('POST', 'https://letterbox.mayursaxena.com/.netlify/functions/received', json=to_send)
        print('{0} {1}: {2}'.format(r.status_code, r.reason, r.text))
        r.close()

    def __decrypt_img(self, json_payload):
        # decrypt key and IV using our RSA private key, then decrypt the image using AES
        dec_key = a2b_base64(rsa_decrypt(a2b_base64(json_payload['k']), self.private_key))
        dec_iv = a2b_base64(rsa_decrypt(a2b_base64(json_payload['i']), self.private_key))
        decryptor = aes(dec_key, 2, dec_iv)
        dec = decryptor.decrypt(a2b_base64(json_payload['d']))
        # server uses DEFLATE to keep sizes down
        return inflate(dec)   

    def bootup(self):
        print('Device has been initialized... Beginning normal bootup.')
        # ensure LetterBox has WiFi, then set the time via NTP
        self.__wifi_manager.get_connection()
        for attempt in range(1,4):
            try:
                settime()
                print('Time set.')
                break
            except:
                print('Error setting time (attempt #{0}).'.format(attempt)))

    def __display_no_letter_text(self):
        # Prompt the user to go register.
        self.__display.clear()
        self.__display.draw_text(0, 0, 'No letters yet!', self.__render_font, 65535)
        self.__display.draw_text(0, 36, 'Register this device to be', self.__render_font, 65535)
        self.__display.draw_text(0, 72, 'able to send letters.', self.__render_font, 65535)
        self.__display.draw_text(0, 108, 'Head on over to:', self.__render_font, 65535)
        self.__display.draw_text(0, 144, 'letterbox.mayursaxena.com', self.__render_font, 65535)
        self.__display.draw_text(0, 180, 'and register this serial #:', self.__render_font, 65535)
        self.__display.draw_text(0, 216, self.serial_number, self.__render_font, 65535)
    
    def __store_keys(self):
        try:
            with open('private.key', 'r') as f:
                print("Storing private key...")
                pri = f.read()
                self.__namespace.set_blob('pri_key', pri)
                self.__namespace.set_i32('pri_key_len', len(pri))
                self.__namespace.commit()
            remove_file('private.key')
            print('Key stored.')
        except OSError:
            pass
        try:
            with open('public.crt', 'r') as f:
                print("Storing public key...")
                pub = f.read()
                self.__namespace.set_blob('pub_key', pub)
                self.__namespace.set_i32('pub_key_len', len(pub))
                self.__namespace.commit()
            remove_file('public.crt')
            print('Key stored.')
        except OSError:
            pass