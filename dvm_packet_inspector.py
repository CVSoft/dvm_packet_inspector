import argparse
import configparser
import hashlib
import json
import queue
import socket
import struct
import sys
import threading
import time

# DVM Packet Inspector, by CVSoft
# Licensed under GPL v3

VERSION = 0x0101

DEFAULT_CONFIG = {
    "Inspector": {
        "ip": "127.0.0.1",
        "port": "54000",
        "peer_id": "0",
        "password":"s3cr37w0rd",
        "use_connect":"true",
        "tickrate":"20.0"
    }
}

def split_cmd_name(msg):
    """Locate command name in a message from master"""
    for i in range(len(msg)):
        if (msg[i] < 65 or msg[i] > 90) and (msg[i] < 48 or msg[i] > 57): break
    if i >= 4:
        return (msg[:i].decode("ascii", "ignore"), msg[i:])
    return (None, msg)

def quick_hex(s):
    """Dump hex contents of a string/bytearray"""
    if type(s) == tuple: s = s[0] # did you pass recvfrom output in here?
    if isinstance(s, str): s = s.encode("windows-1252", "replace")
    return ' '.join(map(lambda q:"{:02X}".format(q), s))


class ConnectionHandler(object):
    def __init__(self, cb):
        """Set up a connection"""
        self.running = True # is the main loop running?
        self.ready = False  # are we connected to the master?
        self.safe = False   # can we delete the thread?
        self.cb = cb # we need this for login
        self.addr = (self.cb.cp.get("Inspector", "ip", fallback="127.0.0.1"),
                     self.cb.cp.getint("Inspector", "port", fallback=54000))
        self.peer_id = struct.pack(">I", cb.cp.getint("Host", "peer_id",
                                                      fallback=0))
        self.connected = self.cb.cp.get("Inspector", "use_connect",
                                        fallback=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(1)
        # debugging aid -- allow both connect() or sendto/recvfrom
        if self.connected:
            self.s.connect(self.addr)
        self.q = queue.Queue()
        self.sendq = queue.Queue()
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()
##        try: self.loop()
##        except KeyboardInterrupt:
##            print("Exiting due to Ctrl-C at console")
##            self.shutdown()

    def loop(self):
        """Do stuff"""
        while self.running and not self.login():
            print("Failed to log in, retrying...")
            for x in range(5): time.sleep(1)
        print("Logged into master")
        # receive packets and queue them
        self.ready = True
        while self.running:
            # receive anything we received...
            try: self.q.put(self.recv())
            except socket.timeout: pass
            except OSError:
                # our socket has been closed
                self.shutdown(send_shutdown=False)
            # ... and send anything we need to send
            try:
                msg = self.sendq.get_nowait()
                self.sendq.task_done()
                self.send(msg)
            except queue.Empty: pass
            time.sleep(0.005)
        self.shutdown(send_shutdown=False)
        self.safe = True

    def shutdown(self, send_shutdown=True):
        """Kill the local process"""
        if send_shutdown: self.send(b"RPTCL"+self.peer_id)
        time.sleep(0.125)
        self.running = False
        try: self.s.close()
        except socket.error: pass

    def asend(self, msg):
        """Send data to the remote master at some point"""
        try: self.sendq.put(msg)
        except queue.Full:
            print("ASend's queue is full! This should never happen!")
            raise queue.Full

    def send(self, msg):
        """Send data to the remote master"""
        if self.connected:
            self.s.send(msg)
        else:
            self.s.sendto(msg, self.addr)

    def recv(self):
        """Receive data from the remote master"""
        if self.connected:
            msg = self.s.recv(2048)
##            print(quick_hex(msg))
            return msg
        else:
            now = time.time()
            while time.time() - now < 1:
                msg, src = self.s.recvfrom(2048)
                if src != self.addr: continue
            raise socket.timeout
##        print(quick_hex(msg))
        return msg

    def login(self):
        try:
            """Log into the remote master"""
            print("Attempting to log into master at {}:{}".format(*self.addr))
            self.send(b"RPTL"+self.peer_id) # implicit bind
            challenge = self.recv()
            assert challenge.startswith(b"RPTACK"), "Did not get challenge ACK"
            assert len(challenge) == 10, "Challenge is of improper length {:d}"\
                   .format(len(challenge))
            res = hashlib.sha256(challenge[6:10]+\
                                 self.cb.cp.get("Inspector", "password",
                                                fallback="")\
                                 .encode("ascii", "ignore")).digest()
            self.send(b"RPTK"+self.peer_id+res)
            res = self.recv()
            assert res.startswith(b"RPTACK"), "Login was not accepted"
            assert len(res) == 10, "Login response is of improper length {:d}"\
                   .format(len(res))
            assert res[6:10] == self.peer_id, \
                   "Login response peer ID mismatch, got {} have {}"\
                   .format(struct.unpack(">I", res[6:10]),
                           struct.unpack(">I", self.peer_id))
            # master expects config. let's get creative
            res = {"identity":"Packet Inspector",
                   "rxFrequency": 0.,
                   "txFrequency": 0.,
                   "info": {
                       "latitude": 0.,
                       "longitude": 0.,
                       "height": 0.,
                       "location": "",
                    },
                   "channel": {
                       "txOffsetMhz": 0.,
                       "chBandwidthKhz": 12.5,
                       "channelId": 0,
                       "channelNo": 0,
                       "txPower": 0,
                    },
                   "rcon": {
                       "password": "ABCD1234",
                       "port": 0
                    }
                   }
            self.send(b"RPTC"+self.peer_id+\
                      json.dumps(res).encode("utf-8", "replace"))
            res = self.recv()
            assert res.startswith(b"RPTACK"), "Config was not accepted"
            assert len(res) == 10, "Config response is of improper length {:d}"\
                   .format(len(res))
            assert res[6:10] == self.peer_id, \
                   "Config response peer ID mismatch, got {} have {}"\
                   .format(struct.unpack(">I", res[6:10]),
                           struct.unpack(">I", self.peer_id))
            return True
        except AssertionError as e:
            print("Login failed! Reason:")
            print(e.args[0])
        except socket.timeout:
            print("Encountered a timeout when communicating with master.")
        return False
        

class PacketInspector(object):
    def __init__(self, cfg_fn):
        self.cp = configparser.RawConfigParser()
        self.cp.read_dict(DEFAULT_CONFIG)
        if cfg_fn: self.cp.read(cfg_fn)
        self.tick_time = 1./self.cp.getfloat("Inspector", "tickrate",
                                             fallback=20.0)
        self.cm = ConnectionHandler(self)
        self.running = True
        try: self.loop()
        except KeyboardInterrupt:
            print("Exiting due to Ctrl-C at console")
            self.shutdown()

    def shutdown(self, kill_main_loop=True):
        """Terminate the ConnectionManager thread and usually our main loop"""
        self.running = not kill_main_loop
        self.cm.shutdown()
        now = time.time()
        while time.time() - now < 2 and not self.cm.safe: time.sleep(0.125)
        del self.cm.t
        del self.cm
        return

    def loop(self):
        time.sleep(0.5)
        if not self.cm.ready:
            print("Waiting for connection handler to report ready status...")
            while not self.cm.ready: time.sleep(0.125)
        last_ping = time.time()
        while self.running:
            now = time.time() # timing reference at start of tick
            # try to receive a packet from the queue
            try:
                msg = self.cm.q.get_nowait()
                self.cm.q.task_done()
            except queue.Empty:
                msg = None
            if msg:
                # look for the command name without using regex
                cmd, data = split_cmd_name(msg)
                if cmd and hasattr(self, "cmd_"+cmd):
                    try: getattr(self, "cmd_"+cmd)(data)
                    except AssertionError: # semi-fatal error handling
                        print(e.args[0])
                elif cmd:
                    self.cmd_unknown(cmd, data)
                else:
                    print("got non-command", repr(msg))
            # ping every 30 seconds
            if now - last_ping > 30:
                last_ping = now
                self.cm.asend(b"RPTPING"+self.cm.peer_id)
            # sleep until next tick
            time.sleep(max(0.005, self.tick_time-(time.time()-now)))

    def cmd_unknown(self, cmd, data):
        print("Got unknown command", cmd, "; Data follows.")
        print(quick_hex(data))
        print(repr(data))
        print()

    def cmd_MSTPONG(self, data):
        """Ping response"""
        assert len(data) == 4, "MSTPONG response is of invalid length {:d}"\
               .format(len(data))
        assert data == self.cm.peer_id, \
               "MSTPONG peer ID mismatch, got {} have {}"\
               .format(struct.unpack(">I", data),
                       struct.unpack(">I", self.cm.peer_id))

    def cmd_P25D(self, data):
        """P25 data packet"""
        p = P25Dissector(data)
        del p


# P25 Dissector stuff

DUIDS = {
    0: "HDU",
    3: "TDU",
    5: "LDU1",
    10: "LDU2",
    11: "PDU",
    15: "TDULC"
}

try: from dvm_packet_inspector_extras import ALGOS
except ImportError:
    ALGOS = {
        0x80: "Clear",
        0x81: "DES-OFB",
        0x84: "AES-256",
        0xAA: "RC4"
    }

try: from dvm_packet_inspector_extras import MFIDS
except ImportError:
    MFIDS = {
        0x00: "P25 Standard",
        0x01: "P25 Non-Standard",
        0x90: "Motorola"
    }

try: from dvm_packet_inspector_extras import LCONAMES
except ImportError:
    LCONAMES = {
        0: ("LC_GRP_V_CH_USR", "Group Voice Channel User", "LCGVR"),
        3: ("LC_UU_V_CH_USR", "Unit to Unit Voice Channel User", "LCUVR"),
    }


class P25Dissector(object):
    """P25 protocol dissector"""
    def __init__(self, data):
        self.d = data
        print("Received {:d} bytes from DVM".format(len(data)))
        print(quick_hex(data))
        print("DVM-provided LCF:", data[0])
        print("DVM-provided Source ID:",
              struct.unpack(">I", b'\x00'+data[1:4])[0])
        print("DVM-provided Target ID:",
              struct.unpack(">I", b'\x00'+data[4:7])[0])
        print("DVM-provided Source Peer:", struct.unpack(">I", data[7:11])[0])
        # see TIA-102.BAAA-A for differentiating frames
        # DUIDs (assume P=0):
        # HDU: 0
        # TDU: 3
        # LDU1: 5 (P=1)
        # LDU2: A (P=1)
        # PDU: B
        # TDULC: F
        duid = data[18] & 0xF
        duid_name = ("" if duid not in DUIDS else DUIDS[duid])
        if duid == 5 and data[176] == 1 and len(data) > 177:
            # The first LDU1 has encryption info attached, as HDUs aren't sent
            # over the network. This allows DVMHost to rebuild the HDU entirely
            # as the LDU1's LC contains all the rest of the information
            # contained in the HDU.
            # See 8.2.1 for HDU structure and 5.2 for Header Word structure
            # See TIA-102.AABF-A 7.3.1 for the LCO for group calls in the LDU1
            # and 7.3.3 for the LCO for unit-to-unit calls.
            #
            # This encryption information is derived from the HDU that wasn't
            # sent.
            # Byte 176 will equal $01 if encryption information is embedded
            # in the LDU1.
            # Byte 177 contains the algorithm ID.
            # Bytes 178-179 contain the key ID.
            # Bytes 180-188 contain the message indicator.
            print("DVM-provided HDU Encryption Information:")
            self._decode_esw(data[177], data[178:180], data[180:189], indent=1)
        print("DUID: ${:02X}".format(duid),
              "" if not duid_name else '('+duid_name+')')
        if hasattr(self, "decode_"+duid_name):
            try: getattr(self, "decode_"+duid_name)(data[20:])
            except AssertionError as e: print(e.args[0])
        print()

    def decode_HDU(self, data):
        # TIA-102.BAAA-A page 10 (22 in PDF); also 8.2.1 (page 36 / 48 in PDF)
        # 72 bits Message Indicator
        # 8 bits Manufacturer ID - need table
        # 8 bits Algorithm ID - need table
        # 16 bits Key ID
        # 16 bits Talkgroup ID - alias 1 and $FFFF, warn on 0
        pass

    def decode_LDU1(self, data):
        assert data[0] == 0x62 and data[22] == 0x63 and data[36] == 0x64 and \
               data[53] == 0x65 and data[70] == 0x66 and data[87] == 0x67 and \
               data[104] == 0x68 and data[121] == 0x69 and data[138] == 0x6A, \
               "Invalid LDU1 frame structure!"
        lc = data[37:40]+data[54:57]+data[71:74]#+data[88:91]
        self.decode_LC(lc)

    def decode_LDU2(self, data):
        assert data[0] == 0x6B and data[22] == 0x6C and data[36] == 0x6D and \
               data[53] == 0x6E and data[70] == 0x6F and data[87] == 0x70 and \
               data[104] == 0x71 and data[121] == 0x72 and data[138] == 0x73, \
               "Invalid LDU2 frame structure!"
        print("Encryption Sync Word information:")
        self._decode_esw(data[88], data[89:91],
                        data[37:40]+data[54:57]+data[71:74])

    def _decode_esw(self, algid, keyid, mi, indent=0):
        """Pretty print encryption sync word info"""
        if isinstance(algid, bytearray): algid = algid[0]
        print(' '*indent+"- Algorithm: ${:02X}".format(algid)+\
              ("" if algid not in ALGOS else " ("+ALGOS[algid]+")"))
        print(' '*indent+"- Key ID   : ${:04X}"\
              .format(struct.unpack(">H", keyid)[0]))
        print(' '*indent+"- Message Indicator:", quick_hex(mi))

    def _decode_vocoder(self, data):
        # u_0 u_1 ... u_7 12*4+11*3+7 = 88 bits
        # DVM should de-interleave this for us
        # TIA-102.BAAA-A page 7 (19 in PDF)
        # b_0 8 bits
        #  period (s) = (b_0 + 39.5) * 0.0000625 s # needed for other values
        #  x = int(4*period+0.25)
        #  l = int(0.9254*x)
        #  k = (36 if l > 36 else int((l+2)/3.))
        #  0 <= b_0 <= 207 is speech
        #  216 <= b_0 <= 219 is silence
        #  all other values are considered Reserved
        # I can probably ignore everything else except Sync
        # b_1 k bits
        # b_2 6 bits
        # b_3 73-k bits
        # b_4 1 bit (always final bit)
        pass

    def decode_LC(self, lc):
        # 72 bits
        # TIA-102.BAAA-A page 14 (26 in PDF)
        # see also entirety of TIA-102.AABF-A about LCF
        # this part varies
        assert len(lc) == 9, "Invalid LC length of {:d}".format(len(lc))
        lco = lc[0] & 0x3F
        if lco in LCONAMES: lci = LCONAMES[lco]
        else: lci = ("Reserved", "Reserved", "R")
        sf = bool(lc[0] & 0x40)
        print("Link Control Word info:")
        print("- LC Opcode:", lco, '('+lci[0]+')')
        print("             [{}]".format(lci[1]))
        print("- LC Contents Protected:", ("Yes" if lc[0] & 0x80 else "No"))
        print("- Standard MFID:", ("Implicit" if sf else "Explicit"))
        if not sf:
            print("- Manufacturer ID: ${:02X}".format(lc[1])+\
                  ("" if lc[1] not in MFIDS else " ("+MFIDS[lc[1]]+")"))
        if lco == 0:
            self._decode_so(lc[2])
            print("- Reserved Octet 3: {:02X}".format(lc[3]))
            print("- Talkgroup ID:", struct.unpack(">H", lc[4:6])[0])
            print("- Source ID   :", struct.unpack(">I", b'\x00'+lc[6:9])[0])
        elif lco == 2 and sf:
            print("- Channel A:", struct.unpack(">H", lc[0:2])[0])
            print("- Group A  :", struct.unpack(">H", lc[2:4])[0])
            print("- Channel A:", struct.unpack(">H", lc[4:6])[0])
            print("- Group A  :", struct.unpack(">H", lc[6:8])[0])
        elif lco == 3:
            self._decode_so(lc[2])
            print("- Target ID:", struct.unpack(">I", b'\x00'+lc[3:6])[0])
            print("- Source ID:", struct.unpack(">I", b'\x00'+lc[6:9])[0])
        else:
            print("Printing LC options not handled for", lci[0])
        

    def _decode_so(self, s):
        """Decode Service Options, used in Link Control Word"""
        print("- Service options:")
        print(" - Emergency:", ("Yes" if s & 0x80 else "No"))
        print(" - Protected:", ("Yes" if s & 0x40 else "No"))
        print(" - Duplex   :", ("Yes" if s & 0x20 else "No"))
        print(" - Mode     :", ("Packet" if s & 0x10 else "Circuit"))
        print(" - Reserved :", ("Set" if s & 0x08 else "Unset"))
        print(" - Priority : {:01X}".format(s & 0x07))


def main():
    ap = argparse.ArgumentParser(\
        description="DVM Packet Inspector by CVSoft v{:x}.{:02x}"\
        .format(VERSION >> 8, VERSION & 0xFF))
    ap.add_argument("fn", nargs="?", default=None)
    a = ap.parse_args()
    pi = PacketInspector(cfg_fn=a.fn)

if __name__ == "__main__" and "idlelib.run" not in sys.modules:
    main()
