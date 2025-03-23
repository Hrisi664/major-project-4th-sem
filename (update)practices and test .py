# --------------- [COMMON SETUP] ---------------
# Run these commands on both systems first:
# pip install rsa pycryptodome pymavlink dronekit
# Generate RSA keys: 
# openssl genrsa -out private.pem 2048
# ssh-keygen -f private.pem -m 'PEM' -e > public.pem

# --------------- [GROUND CONTROL STATION CODE] ---------------
import rsa
import socket
import json
import time
from dronekit import connect, Command

class GroundControl:
    def __init__(self, drone_ip='192.168.0.10'):
        self.drone_ip = drone_ip
        self.control_port = 14550
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.load_keys()
        
    def load_keys(self):
        with open('ground_private.pem') as f:
            self.priv_key = rsa.PrivateKey.load_pkcs1(f.read())
        with open('drone_public.pem') as f:
            self.drone_pub_key = rsa.PublicKey.load_pkcs1(f.read())

    def encrypt(self, message):
        return rsa.encrypt(json.dumps(message).encode(), self.drone_pub_key)

    def decrypt(self, ciphertext):
        return json.loads(rsa.decrypt(ciphertext, self.priv_key).decode())

    def send_command(self, cmd_type, params={}):
        command = {
            'timestamp': time.time(),
            'cmd': cmd_type,
            'params': params
        }
        self.sock.sendto(self.encrypt(command), (self.drone_ip, self.control_port))

    def mission_planner(self):
        mission = [
            {'type': 'TAKEOFF', 'alt': 10},
            {'type': 'WAYPOINT', 'lat': -35.363261, 'lon': 149.165230, 'alt': 20},
            {'type': 'RTL'}
        ]
        for step in mission:
            self.send_command('MISSION_STEP', step)
            while True:
                data, _ = self.sock.recvfrom(4096)
                ack = self.decrypt(data)
                if ack.get('status') == 'ACK':
                    break

    def start(self):
        self.send_command('ARM')
        self.send_command('MODE', {'mode': 'GUIDED'})
        self.mission_planner()

if __name__ == "__main__":
    gcs = GroundControl()
    gcs.start()

# --------------- [DRONE CODE (Raspberry Pi)] ---------------
from pymavlink import mavutil
import threading

class DroneSystem:
    def __init__(self):
        self.vehicle = mavutil.mavlink_connection('/dev/ttyACM0', baud=921600)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 14550))
        self.load_keys()
        self.running = True
        
    def load_keys(self):
        with open('drone_private.pem') as f:
            self.priv_key = rsa.PrivateKey.load_pkcs1(f.read())
        with open('ground_public.pem') as f:
            self.gcs_pub_key = rsa.PublicKey.load_pkcs1(f.read())

    def decrypt(self, data):
        return json.loads(rsa.decrypt(data, self.priv_key).decode())

    def encrypt(self, message):
        return rsa.encrypt(json.dumps(message).encode(), self.gcs_pub_key)

    def execute_command(self, command):
        cmd_type = command['cmd']
        params = command.get('params', {})
        
        if cmd_type == 'ARM':
            self.vehicle.arducopter_arm()
        elif cmd_type == 'MODE':
            self.vehicle.set_mode(params['mode'])
        elif cmd_type == 'MISSION_STEP':
            self.handle_mission_step(params)
            
        return {'status': 'ACK', 'timestamp': time.time()}

    def handle_mission_step(self, step):
        if step['type'] == 'TAKEOFF':
            self.vehicle.mav.command_long_send(
                0, 0, mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
                0, 0, 0, 0, 0, 0, 0, step['alt']
            )
        elif step['type'] == 'WAYPOINT':
            self.vehicle.mav.mission_item_send(
                0, 0, 0, mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT,
                mavutil.mavlink.MAV_CMD_NAV_WAYPOINT, 0, 0, 0, 0, 0, 0,
                step['lat'], step['lon'], step['alt']
            )
        elif step['type'] == 'RTL':
            self.vehicle.set_mode('RTL')

    def telemetry_thread(self):
        while self.running:
            status = {
                'gps': self.vehicle.location.global_frame,
                'battery': self.vehicle.battery,
                'attitude': self.vehicle.attitude
            }
            self.sock.sendto(self.encrypt(status), ('192.168.0.5', 14550))
            time.sleep(0.1)

    def command_thread(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                command = self.decrypt(data)
                response = self.execute_command(command)
                self.sock.sendto(self.encrypt(response), addr)
            except Exception as e:
                print(f"Command error: {str(e)}")

if __name__ == "__main__":
    drone = DroneSystem()
    threading.Thread(target=drone.telemetry_thread).start()
    threading.Thread(target=drone.command_thread).start()
