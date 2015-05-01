from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *
from ipaddress import IPv4Network, IPv4Address
import time

class Firewall(object):

    def __init__(self, net, rules):
        self.net       = net
        self.portnames = [ p.name for p in net.ports() ]
        self.portpair  = dict(zip(self.portnames, self.portnames[::-1]))
        self.rules     = rules
        self.pkt       = None


    def run(self):
        while True:
            got_packet = True
            try:
                port, pkt = self.net.recv_packet()
            except NoPackets:
                log_debug("No packets available in recv_packet")
                got_packet = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if got_packet:
                self.pkt = pkt
                if self.forward_packet(pkt):
                    self.net.send_packet(self.portpair[port], pkt)

        self.net.shutdown()


    def forward_packet(self, p):
        # for impair...just drops 50% of packets in flow
        if p.has_header(Arp) or p.has_header(IPv6):
            return True
        elif not p.has_header(IPv4):
            return False

        if p.has_header(TCP):
            p_srcport = p.get_header(TCP).srcport
            p_dstport = p.get_header(TCP).dstport
        elif p.has_header(UDP):
            p_srcport = p.get_header(UDP).srcport
            p_dstport = p.get_header(UDP).dstport
        else:
            p_srcport, p_dstport = None, None

        for r in self.rules:
            if ((r.protocol == 'tcp' and p.has_header(TCP))
                or (r.protocol == 'udp' and p.has_header(UDP))):
                if (self.ip_match(r.src, p[1].srcip)
                    and self.ip_match(r.dst, p[1].dstip)):
                    if (self.port_match(r.srcport, p_srcport)
                        and self.port_match(r.dstport, p_dstport)):
                        if r.rate_limit:
                            r.bucket.add_tokens()
                            return r.bucket.remove_tokens(p)
                        elif r.impair:
                            return True if random.random() <= 0.5 else False
                        else:
                            return True if r.action == 'permit' else False
                    else:
                        continue
                else:
                    continue
            elif ((r.protocol == 'ip' and p.has_header(IPv4))
                  or (r.protocol == 'icmp' and p.has_header(ICMP))):
                if (self.ip_match(r.src, p[1].srcip)
                    and self.ip_match(r.dst, p[1].dstip)):
                    if r.rate_limit:
                        r.bucket.add_tokens()
                        return r.bucket.remove_tokens(p)
                    elif r.impair:
                        return True if random.random() <= 0.5 else False
                    else:
                        return True if r.action == 'permit' else False
                else:
                    continue
            else:
                continue


    def ip_match(self, rule_address, packet_address):
        if rule_address == 'any':
            return True
        else:
            rule_address = IPv4Network(rule_address)
            return True if packet_address in rule_address else False


    def port_match(self, rule_port, packet_port):
        if rule_port == 'any':
            return True
        else:
            return True if rule_port == str(packet_port) else False


class TokenBucket(object):

    def __init__(self, rule):
        self.last_update = time.time()
        self.rate_limit  = int(rule.rate_limit)
        self.max_tokens  = self.rate_limit * 2
        self.tokens      = self.max_tokens


    def add_tokens(self):
        num = (time.time() - self.last_update) / 0.5
        self.tokens += (num * (self.rate_limit / 2))
        self.last_update = time.time()
        if self.tokens > self.max_tokens:
            self.tokens = self.max_tokens


    def remove_tokens(self, packet):
        total_pkt_size = len(packet)

        if packet.has_header(Ethernet):
            size = total_pkt_size - len(packet.get_header(Ethernet))
        else:
            size = total_pkt_size

        if self.tokens >= size:
            self.tokens -= size
            if self.tokens < 0:
                self.tokens = 0
            return True
        else:
            return False

class Rules(object):

    def __init__(self):
        self.lyst = self.parse_txt_file('firewall_rules.txt')


    def parse_txt_file(self, filename):
        filename    = "firewall_rules.txt"
        file_object = open(filename, 'r')
        rules       = []

        for line in file_object:

            if line.startswith("# rule "):
                line = file_object.readline().strip().split()
                rule = Rule(action=line[0], protocol=line[1],
                            src=line[3], dst=line[5])

                if line[0] == 'permit':
                    if line[-2] == 'ratelimit':
                        rule.rate_limit = line[-1]
                        rule.bucket     = TokenBucket(rule)
                    elif line[-1] == 'impair':
                        rule.impair = True

                if len(line) >= 10:
                    rule.srcport = line[5]
                    rule.dst     = line[7]
                    rule.dstport = line[9]

                rules.append(rule)

        file_object.close()
        return rules


class Rule(object):

    def __init__(self, action, protocol, src, dst):
        self.action     = action
        self.protocol   = protocol
        self.src        = src
        self.dst        = dst
        self.srcport    = None
        self.dstport    = None
        self.rate_limit = None
        self.impair     = False
        self.bucket     = None


def switchy_main(net):
    rules    = Rules().lyst
    firewall = Firewall(net, rules)
    firewall.run()

