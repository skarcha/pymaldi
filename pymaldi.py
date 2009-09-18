# -*- coding: utf-8 -*-
"""
   Copyright 2009 Antonio Pérez Jiménez
                  David Prieto Carrellán

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
import socket
import threading
import Queue
import logging


PYMALDI_VERSION = 0.3
STX = '\002'
ETX = '\003'
BUFLEN = 2048
EVENTS_OP = (0x09, 0x30, 0x40, 0x60, 0x80, 0x81, 0x82, 0x83, 0x4B)


class NullHandler(logging.Handler):
    def emit(self, record):
        pass


class Pymaldi():

    def __init__ (self, logger_name=None):
        self.__phase   = 1
        self.__qComAns = Queue.Queue()
        self.__qEvents = Queue.Queue()
        self.__qwCommandAns = Queue.Queue()
        if logger_name:
            logger_name += '.pymaldi'
        else:
            logger_name = 'pymaldi'
        self.__logger = logging.getLogger(logger_name)
        self.__logger.addHandler(NullHandler())

    def onReset(self, data):
        pass

    def onReadCard(self, card_id):
        pass

    def onKeyPress(self, key):
        pass

    def onTempLED(self, color, time):
        pass

    def onTempBeeper(self, beeper, time):
        pass

    def onDigitalInput(self, status):
        pass

    def onDefault(self, data):
        pass

    def __create_threads(self):
        self.thd_reader = threading.Thread(None, self.__read_from_terminal)
        self.thd_reader.setDaemon(True)
        self.thd_reader.start()
        self.thd_events = threading.Thread(None, self.__process_events)
        self.thd_events.setDaemon(True)
        self.thd_events.start()

    def wait_events(self):
        self.thd_reader.join(5)
        self.thd_events.join(5)

    def OpenPortUDP (self, rAddress, remotePort=5500, localPort=5501):
        if self.__phase > 1:
            return 1

        if not rAddress:
            self.__logger.critical("Remote address is needed")
            return 3

        self.remoteAddress = rAddress
        self.remotePort = remotePort
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('', localPort))
        except:
            self.__logger.critical("Error opening UDP port: %s:%s" % (rAddress, localPort))
            return 4

        self.__create_frame = self.__create_udp_frame
        self.__send_frame = self.__send_udp_frame
        self.__recv_answer = self.__recv_udp_answer
        self.__phase = 2
        self.__create_threads()
        return 0


    def OpenPortTCP (self, rAddress, remotePort=1001, localPort=0):
        if self.__phase > 1:
            return 1

        if not rAddress:
            self.__logger.critical("Remote address is needed")
            return 3

        self.remoteAddress = rAddress
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((rAddress, remotePort))
        except:
            self.__logger.critical("Error connecting to: %s:%s" % (rAddress, remotePort))
            return 4

        self.__create_frame = self.__create_tcp_frame
        self.__send_frame = self.__send_tcp_frame
        self.__recv_answer = self.__recv_tcp_answer
        self.__phase = 2
        self.__create_threads()
        return 0


    def SetUpBIOMAX2 (self, model=0):
        re = self.HotReset()
        if not re:
            self.__phase = 3
        return re


    def HotReset (self):
        if self.__phase < 2:
            return 1

        return self.__process_command(0x01, '')


    def GetConfig (self, param):
        if self.__phase < 3:
            return self.__phase

        re, ans = self.__command_and_answer(0x0A, chr(param))
        if re:
            return re, ans
        else:
            if ans[2] != '\x02':
                return 255, 'Short answer: %s' % ans
            else:
                return 0, ord(ans[4])


    def SetConfig (self, param, value):
        if self.__phase < 3:
            return self.__phase

        re, ans = self.__command_and_answer(0x0B, chr(param) + chr(value))
        if re:
            return re
        else:
            if (ans[2] != '\x01') or (ans[3] != chr(param)):
                return 255
            return 0


    def ApplyConfig (self):
        if self.__phase < 3:
            return 1

        return self.__process_command(0x09, '')


    def ActivateDigitalOutput (self, numout, time):
        if self.__phase < 3:
            return self.__phase

        if numout < 0 or numout > 3 or time < 0 or time > 254:
            return 255

        if numout == 3 and time > 0x19:
            return 255

        data = chr(numout) + chr(time)
        return self.__process_command(0x30, data)


    def SwitchDigitalOutput (self, numout, value):
        if self.__phase < 3:
            return self.__phase

        if numout < 0 or numout > 3:
            return 255

        if value:
            switch = 1
        else:
            switch = 0

        data = chr(numout) + chr(switch)
        return self.__process_command(0x31, data)


    def ActivateRelay (self, numrelay, time):
        if self.__phase < 3:
            return self.__phase

        if numrelay < 0 or numrelay > 3:
            return 11
        if time > 254:
            return 255

        data = chr(numrelay) + chr(time)
        return self.__process_command(0x40, data)


    def SwitchRelay (self, numrelay, value):
        if self.__phase < 3:
            return self.__phase

        if numrelay < 0 or numrelay > 3:
            return 255

        if value:
            switch = 1
        else:
            switch = 0

        data = chr(numrelay) + chr(switch)
        return self.__process_command(0x41, data)


    def WriteDisplay (self, text):
        if self.__phase < 3:
            return self.__phase

        data = '%-40s' % text[0:40]
        return self.__process_command(0x11, data)


    def WriteDisplay2 (self, text, light, beep):
        if self.__phase < 3:
            return self.__phase

        if light > 255 or beep > 255:
            return 255

        data = chr(light) + chr(beep) + '%-40s' % text[0:40]
        return self.__process_command(0x14, data)


    def ClearDisplay (self):
        if self.__phase < 3:
            return self.__phase

        return self.__process_command(0x10, '')


    def DigitalInputStatus (self):
        if self.__phase < 3:
            return self.__phase

        re, ans = self.__command_and_answer(0x60, '')
        if re:
            return re, ans
        else:
            return 0, ord(ans[3])


    # Private methods.
    # ----------------------------------------
    def __read_from_terminal (self):
        while True:
            try:
                ans = self.__recv_answer()
            except:
                continue

            if self.__is_event(ans):
                self.__qEvents.put(ans)
            else:
                self.__qComAns.put(ans)

            # self.__show_buffer(ans)


    def __process_events (self):
        while True:
            ans_event = self.__qEvents.get(True)
            opc = ord(ans_event[0])
            na  = (ord(ans_event[1]) << 8) + ord(ans_event[2])

            if opc == 0x09: # onReset
                if callable(self.onReset):
                    if na == 0x00:
                        self.onReset('')
                    else:
                        self.onReset(self.__byte_to_hex(ans_event[3:3+na]))

            elif opc == 0x81: # Card read
                if callable(self.onReadCard):
                    if na != 0x00:
                        card_id = ans_event[3:3+na]
                    else:
                        card_id = ''
                    self.onReadCard(card_id)

            elif opc == 0x80: # Key press
                if na != 0x00 and callable(self.onKeyPress):
                    self.onKeyPress(ans_event[3:3+na])

            elif opc == 0x30: # Temp. Activate Led/Beeper
                if na != 0x00:
                    etype = ord(ans_event[3])
                    time  = ord(ans_event[4])
                    if etype in (0x00, 0x01) and callable(self.onTempLED):
                        if etype == 0x00:
                            self.onTempLED('green', time)
                        elif etype == 0x01:
                            self.onTempLED('red', time)
                    elif etype in (0x02, 0x03) and callable(self.onTempBeeper):
                        if etype == 0x02:
                            self.onTempBeeper('external', time)
                        elif etype == 0x03:
                            self.onTempBeeper('internal', time)

            elif opc == 0x60: # OnDigitalInput
                if na != 0x00 and callable(self.onDigitalInput):
                    self.onDigitalInput(ord(ans_event[3:3+na]))

            else: # Other events
                if callable(self.onDefault):
                    self.onDefault(ans_event[:-1])


    def __is_event (self, ans):
        opc = ord(ans[0])
        if not opc in EVENTS_OP:
            return False
        else:
            try:
                wopc = self.__qwCommandAns.get(False)
                if wopc == opc:
                    return False
            except Queue.Empty:
                pass

        return True

    def __process_command (self, opc, data):
        ans = self.__send_command (opc, data)
        if not ans:
            return 255
        return 0

    def __command_and_answer (self, opc, data):
        ans = self.__send_command (opc, data)
        if not ans:
            return (255, '')

        return (0, ans)

    def __send_command (self, opc, data):
        if opc in EVENTS_OP:
            self.__qwCommandAns.put(opc)
        self.__send_frame(self.__create_frame(opc, data))
        try:
            ans = self.__qComAns.get(True, 5)
            if not self.__validate_data (opc, ans):
                self.__show_buffer(ans)
                ans = None
        except Queue.Empty:
            self.__logger.debug("No answer received from terminal")
            ans = None

        return ans

    def __validate_data (self, opc, data_answer):
        opc_answer = ord(data_answer[0])
        len_answer = (ord(data_answer[1]) << 8) + ord(data_answer[2])
        crc_answer = ord(data_answer[-1])

        if opc != opc_answer:
            self.__logger.error("Operation code error")
            return False

        crc = self.__get_crc(self.__get_data_crc(opc_answer, data_answer[3:3+len_answer]))

        if crc_answer != crc:
            self.__logger.error("CRC error!: %0.2X" % crc)
            return False

        return True

    def __send_tcp_frame (self, frame):
        self.socket.send(frame)

    def __send_udp_frame (self, frame):
        self.socket.sendto(frame, (self.remoteAddress, self.remotePort))

    def __recv_tcp_answer (self):
        answer = self.socket.recv(BUFLEN)
        return self.__hex_to_byte(answer[1:-1])

    def __recv_udp_answer (self):
        (answer, (ip, port)) = self.socket.recvfrom(BUFLEN)
        if ip != self.remoteAddress and port != self.remotePort:
            raise Exception, "Data not expected from this IP: %s:%s" % (ip, port)
            return

        return answer

    def __create_tcp_frame(self, operation, data):
        data_crc = self.__get_data_crc(operation, data)
        crc =  self.__get_crc(data_crc)

        return STX + data_crc + "%0.2X" % crc + ETX

    def __create_udp_frame(self, operation, data):
        leng = len(data)
        length_hex = chr(leng >> 8) + chr(leng & 0xff)
        CRC = self.__get_crc(self.__get_data_crc(operation, data))

        return chr(operation) + length_hex + data + chr(CRC)

    def __get_data_crc (self, operation, data):
        str_operation = "%0.2X" % operation
        length_hex = "%0.4X" % len(data)

        data_hex = self.__byte_to_hex (data)

        return str_operation + length_hex + data_hex

    def __get_crc (self, data_crc):
        crc = 0
        for i in data_crc:
            crc += ord(i)
        crc %= 256

        return crc

    def __hex_to_byte (self, hex_str):
        bytes = ''
        for i in range(0, len(hex_str), 2):
            bytes += chr(int(hex_str[i:i+2], 16))

        return bytes

    def __byte_to_hex (self, bytes):
        data_hex = ''
        for i in bytes:
            data_hex += "%0.2X" % ord(i)

        return data_hex

    def __show_buffer(self, buf):
        if buf:
            msg = ''
            for i in buf:
                msg += hex(ord(i))
            self.__logger.critical(msg)
