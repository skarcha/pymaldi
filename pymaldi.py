# -*- coding: utf-8 -*-
"""
   Copyright 2009 Antonio Pérez Jiménez

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

STX = '\002'
ETX = '\003'
BUFLEN = 2048
EVENTS_OP = (0x09, 0x30, 0x40, 0x60, 0x80, 0x81, 0x82, 0x83, 0x4B)

class Pymaldi():

    def __init__ (self):
        self.__phase      = 1
        self.__qComAns    = Queue.Queue()
        self.__qEvents    = Queue.Queue()

    def onReadCard(self, card_id):
        pass

    def onKeyPress(self, key):
        pass

    def onTempLED(self, color, time):
        pass

    def onTempBeeper(self, beeper, time):
        pass

    def onDefault(self, data):
        pass

    def __create_threads(self):
        self.thd_reader = threading.Thread(None, self.__read_from_terminal)
        self.thd_reader.start()
        self.thd_events = threading.Thread(None, self.__process_events)
        self.thd_events.start()

    def wait_events(self):
        self.thd_reader.join(5)
        self.thd_events.join(5)

    def OpenPortUDP (self, rAddress, remotePort=5500, localPort=5501):
        if self.__phase > 1:
            return 1

        if not rAddress:
            print "Remote address is needed"
            return 3

        self.remoteAddress = rAddress
        self.remotePort = remotePort
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind(('', localPort))
        except:
            print "Error opening UDP port: %s:%s" % (rAddress, localPort)
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
            print "Remote address is needed"
            return 3

        self.remoteAddress = rAddress
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((rAddress, remotePort))
        except:
            print "Error connecting to: %s:%s" % (rAddress, remotePort)
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

        return self.__send_command(0x01, '', '\x01\x00\x00\x21')


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


    def ActivateDigitalOutput (self, numout, time):
        if self.__phase < 3:
            return self.__phase

        if numout < 0 or numout > 3 or time < 0 or time > 254:
            return 255

        if numout == 3 and time > 0x19:
            return 255

        data = chr(numout) + chr(time)
        return self.__send_command(0x30, data, '\x30\x00\x00\x23')


    def ActivateRelay (self, numrelay, time):
        if self.__phase < 3:
            return self.__phase

        if numrelay < 0 or numrelay > 3:
            return 11
        if time > 254:
            return 255

        data = chr(numrelay) + chr(time)
        return self.__send_command(0x40, data, '\x40\x00\x00\x24')


    def WriteDisplay (self, text):
        if self.__phase < 3:
            return self.__phase

        data = '%-40s' % text[0:40]
        return self.__send_command(0x11, data, '\x11\x00\x00\x22')


    def WriteDisplay2 (self, text, light, beep):
        if self.__phase < 3:
            return self.__phase

        if light > 255 or beep > 255:
            return 255

        data = chr(light) + chr(beep) + '%-40s' % text[0:40]
        return self.__send_command(0x14, data, '\x14\x00\x00\x25')


    def ClearDisplay (self):
        if self.__phase < 3:
            return self.__phase

        return self.__send_command(0x10, '', '\x10\x00\x00\x21')



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

            if opc == 0x81: # Card read
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

            else: # Other events
                if callable(self.onDefault):
                    self.onDefault(ans_event[:-1])


    def __is_event (self, ans):
        opc = ord(ans[0])
        if not opc in EVENTS_OP:
            return False
        else:
            if (opc == 0x30 or opc == 0x40) and ord(ans[2]) == 0x00:
                return False

        return True

    def __send_command (self, opc, data, exptd_ans):
        self.__send_frame(self.__create_frame(opc, data))
        try:
            ans = self.__qComAns.get(True, 5)
        except Queue.Empty:
            print "No answer received from terminal"
            return 255

        if ans != exptd_ans:
            print "Unexpected answer:",
            for i in ans:
                print hex(ord(i)),
            return 255
        return 0

    def __command_and_answer (self, opc, data):
        self.__send_frame(self.__create_frame(opc, data))
        try:
            ans = self.__qComAns.get(True, 5)
        except Queue.Empty:
            print "No answer received from terminal"
            return 255

        if ans[0] != '\x0A':
            return (255, '')

        return (0, ans)

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

        return STX + data_crc +"%0.2X" % crc + ETX

    def __create_udp_frame(self, operation, data):
        leng = len(data)
        length_hex = chr(leng >> 8) + chr(leng & 0xff)
        CRC = self.__get_crc(self.__get_data_crc(operation, data))

        return chr(operation) + length_hex + data + chr(CRC)

    def __get_data_crc (self, operation, data):
        str_operation = "%0.2X" % operation
        length_hex = "%0.4X" % len(data)

        data_hex = ''
        for i in data:
            data_hex += "%0.2X" % ord(i)

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

    def __show_buffer(self, buf):
        for i in buf:
            print hex(ord(i)),
        print