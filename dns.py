import socket
import struct
import json
import os
from time import time


class Server:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 53))

    def start(self):
        print('\nServer has been started!\n')
        cache = Cache()
        cache.load()
        while True:
            data, addr = self.socket.recvfrom(512)
            request = read_packet(data)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
                cache.delete()
                answers = []
                authority = []
                additional = []
                for question in request.questions:
                    cached_rr = cache.find(question.qname, question.qtype, question.qclass)
                    if cached_rr is None:
                        header = Header(questions_count=1, rd=1)
                        dns_request = Packet(header, [question])
                        try:
                            server_socket.sendto(dns_request.to_bytes(), (forwarder, 53))
                            answer = server_socket.recvfrom(512)[0]
                            dns_answer = read_packet(answer)
                            answers.extend(dns_answer.answer_rrs)
                            authority.extend(dns_answer.authority_rrs)
                            additional.extend(dns_answer.additional_rrs)
                            print('New cache record has been made!')
                            for answer in answers:
                                cache.add(answer)
                            for answer in authority:
                                cache.add(answer)
                            for answer in additional:
                                cache.add(answer)
                        except:
                            pass
                    else:
                        for answer in cached_rr:
                            answers.append(answer)
                        print('Cache has been used!')
                my_answer = new_response(request.header.id, request.questions, answers)
                self.socket.sendto(my_answer.to_bytes(), addr)
                cache.save()
                print("Response has been sent!")


class Header:
    def __init__(self, id=0, qr=0, opcode=0, rd=0,
                 questions_count=0, ancount=0, nscount=0, arcount=0):
        self.id = id
        self.qr = qr
        self.opcode = opcode
        self.aa = 0
        self.tc = 0
        self.rd = rd
        self.ra = 0
        self.z = 0
        self.rcode = 0
        self.qdcount = questions_count
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def __str__(self):
        return str(self.id) + ' ' + str(self.qr) + ' ' + str(self.opcode) + ' ' \
               + str(self.aa) + ' ' + str(self.tc) + ' ' + str(self.rd) + ' ' \
               + str(self.ra) + ' ' + str(self.z) + ' ' + str(self.rcode) + ' ' \
               + str(self.qdcount) + ' ' + str(self.ancount) + ' ' + str(self.nscount) + ' ' + str(self.arcount)

    def to_bytes(self):
        res = b''
        res += struct.pack('!H', self.id)
        res += struct.pack('!B', self.qr << 7 | self.opcode << 3 | self.aa << 2 | self.tc << 1 | self.rd)
        res += struct.pack('!B', self.ra << 7 | self.z << 3 | self.rcode)
        res += struct.pack('!HHHH', self.qdcount, self.ancount, self.nscount, self.arcount)
        return res

    def from_bytes(self, data, start_index):
        fields = struct.unpack('!HBBHHHH', data[start_index:struct.calcsize('!HBBHHHH')])
        self.id = fields[0]
        self.qr = fields[1] >> 7 & 0x1
        self.opcode = fields[1] >> 3 & 0b1111
        self.aa = fields[1] >> 2 & 0x1
        self.tc = fields[1] >> 1 & 0x1
        self.rd = fields[1] & 0x1  # rd
        self.ra = fields[2] >> 7 & 0x1
        self.z = fields[2] >> 3 & 0x7
        self.rcode = fields[2] & 0b1111
        self.qdcount = fields[3]
        self.ancount = fields[4]
        self.nscount = fields[5]
        self.arcount = fields[6]
        return 12

    def to_dict(self):
        return {
            'id': self.id, 'qr': self.qr, 'opcode': self.opcode,
            'aa': self.aa, 'tc': self.tc, 'rd': self.rd,
            'ra': self.ra, 'z': self.z, 'rcode': self.rcode,
            'qdcount': self.qdcount, 'ancount': self.ancount,
            'nscount': self.nscount, 'arcount': self.arcount
        }

    def from_dict(self, dict):
        self.id = int(dict['id'])
        self.qr = int(dict['qr'])
        self.opcode = int(dict['opcode'])
        self.aa = int(dict['aa'])
        self.tc = int(dict['tc'])
        self.rd = int(dict['rd'])
        self.ra = int(dict['ra'])
        self.z = int(dict['z'])
        self.rcode = int(dict['rcode'])
        self.qdcount = int(dict['qdcount'])
        self.ancount = int(dict['ancount'])
        self.nscount = int(dict['nscount'])
        self.arcount = int(dict['arcount'])


def name_to_bytes(name):
    name_parts = name.split('.')
    chars_lists = ([char for char in part] for part in name_parts)
    result = b''
    for char_gen in chars_lists:
        result += struct.pack('!B', len(char_gen))
        for char in char_gen:
            result += struct.pack('!c', char.encode('ASCII'))
    if result != b'\x00':
        result += struct.pack('!B', 0)
    return result


def name_from_bytes(data, index=0):
    domain_name = []
    count = data[index]
    while count != 0:
        if count >= 192:
            index += 1
            hop = (count << 2 & 0b111111) + data[index]
            name, _ = name_from_bytes(data, hop)
            domain_name.append(name)
            return '.'.join(domain_name), index + 1
        else:
            index += 1
            domain = data[index:index + count]
            decoded = domain.decode()
            domain_name.append(decoded)
            index += count
            count = data[index]
    return '.'.join(domain_name), index + 1


def rdata_from_bytes(data, start_index, end_index, a_type):
    if a_type ==1:
        data = data[start_index:end_index]
        return '{0}.{1}.{2}.{3}'.format(data[0], data[1], data[2], data[3])
    elif a_type == 28:
        data = data[start_index:end_index]
        return data
    else:
        name, _ = name_from_bytes(data, start_index)
        return name


def rdata_to_bytes(rdata, a_type):
    if rdata == '':
        return b''
    if a_type == 1:
        parts = rdata.split('.')
        return struct.pack('!BBBB', int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))
    elif a_type == 28:
        try:
            return bytes(rdata)
        except:
            return rdata.replace('b', '').replace('\'', '').encode()
    else:
        return name_to_bytes(rdata)


class Question:
    def __init__(self, qname='', qtype=1, qclass=1):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def __str__(self):
        return self.qname + ' ' + str(self.qtype) + ' ' + str(self.qclass)

    def to_bytes(self):
        res = b''
        res += name_to_bytes(self.qname)
        res += struct.pack('!hh', self.qtype, self.qclass)
        return res

    def from_bytes(self, data, start_index):
        self.qname, offset = name_from_bytes(data, start_index)
        ndt = data[offset:offset + 4]
        fields = struct.unpack('!hh', ndt)
        self.qtype = fields[0]
        self.qclass = fields[1]
        return offset + 4

    def to_dict(self):
        return {
            'qname': self.qname,
            'qtype': self.qtype,
            'qclass': self.qclass
        }

    def from_dict(self, dictionary):
        self.qname = dictionary['qname']
        self.qtype = dictionary['qtype']
        self.qclass = dictionary['qclass']

    def to_json(self):
        return json.dumps(self.to_dict())

    def from_json(self, json_str):
        dictionary = json.loads(json_str)
        self.from_dict(dictionary)


class ResourceRecord:
    def __init__(self, name='', type=2, rrclass=1, ttl=100, rdlength=0, rdata=''):
        self.name = name
        self.type = type
        self.rr_class = rrclass
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata = rdata

    def __str__(self):
        return self.name + '|' + str(self.type) + '|' \
               + str(self.rr_class) + '|' + str(self.ttl) + '|' \
               + str(self.rdlength) + '|' + str(self.rdata)

    def to_bytes(self):
        res = b''
        res += name_to_bytes(self.name)
        res += struct.pack('!H', self.type)
        res += struct.pack('!H', self.rr_class)
        res += struct.pack('!I', self.ttl)
        rdata = rdata_to_bytes(self.rdata, self.type)
        res += struct.pack('!H', len(rdata))
        res += rdata
        return res

    def from_bytes(self, data, start_index):
        self.name, offset = name_from_bytes(data, start_index)
        l = struct.calcsize('!HHIH')
        nd = data[offset:offset + l]
        fields = struct.unpack('!HHIH', nd)
        self.type = fields[0]
        self.rr_class = fields[1]
        self.ttl = fields[2]
        self.rdlength = fields[3]
        self.rdata = rdata_from_bytes(data, offset + l, offset + l + self.rdlength, self.type)
        return offset + l + self.rdlength

    def to_dict(self):
        return {
            'name': self.name,
            'type': self.type,
            'class': self.rr_class,
            'ttl': self.ttl,
            'rdlength': self.rdlength,
            'rdata': self.rdata
        }

    def from_dict(self, dictionary):
        self.name = dictionary['name']
        self.type = int(dictionary['type'])
        self.rr_class = int(dictionary['class'])
        self.ttl = int(dictionary['ttl'])
        self.rdlength = int(dictionary['rdlength'])
        self.rdata = dictionary['rdata']

    def to_json(self):
        return json.dumps(self.to_dict())

    def from_json(self, json_str):
        dictionary = json.loads(json_str)
        self.from_dict(dictionary)


class Packet:
    def __init__(self, header=Header(), questions=None,
                 answer_rrs=None, authority_rrs=None, additional_rrs=None):
        self.header = header

        self.questions = questions

        self.answer_rrs = answer_rrs
        self.authority_rrs = authority_rrs
        self.additional_rrs = additional_rrs

    def to_bytes(self):
        result = b''
        result += self.header.to_bytes()
        for question in self.questions:
            result += question.to_bytes()
        if self.answer_rrs is not None:
            for answer in self.answer_rrs:
                result += answer.to_bytes()
        if self.authority_rrs is not None:
            for auth_rr in self.authority_rrs:
                result += auth_rr.to_bytes()
        if self.additional_rrs is not None:
            for add_rr in self.additional_rrs:
                result += add_rr.to_bytes()
        return result

    def to_dict(self):
        return {
            'header': self.header.to_dict(),
            'question': [question.to_dict() for question in self.questions],
            'answer': [answer.to_dict() for answer in self.answer_rrs if self.answer_rrs is not None],
            'authority': [answer.to_dict() for answer in self.authority_rrs if self.authority_rrs is not None],
            'additional': [answer.to_dict() for answer in self.additional_rrs if self.additional_rrs is not None]
        }

    def from_dict(self, dictionary):
        self.header = Header()
        self.header.from_dict(dictionary['header'])

        self.questions = []
        for question in dictionary['questions']:
            q = Question()
            q.from_dict(question)
            self.questions.append(q)

        self.answer_rrs = []
        for answer in dictionary['answer']:
            rr = ResourceRecord()
            rr.from_dict(answer)
            self.answer_rrs.append(rr)

        self.authority_rrs = []
        for answer in dictionary['authority']:
            rr = ResourceRecord()
            rr.from_dict(answer)
            self.authority_rrs.append(rr)

        self.additional_rrs = []
        for answer in dictionary['additional']:
            rr = ResourceRecord()
            rr.from_dict(answer)
            self.additional_rrs.append(rr)

    def to_json(self):
        return json.dumps(self.to_dict())

    def from_json(self, json_str):
        dictionary = json.loads(json_str)
        self.from_dict(dictionary)


def read_packet(data):
    header = Header()
    offset = header.from_bytes(data, 0)

    def read_question(data, index):
        question = Question()
        index = question.from_bytes(data, index)
        return question, index

    questions = []
    for _ in range(header.qdcount):
        question, offset = read_question(data, offset)
        questions.append(question)

    def read_rr(data, index):
        answer_rr = ResourceRecord()
        index = answer_rr.from_bytes(data, index)
        return answer_rr, index

    answer, authority, additional = [], [], []
    for _ in range(header.ancount):
        ans, offset = read_rr(data, offset)
        answer.append(ans)
    for _ in range(header.nscount):
        auth, offset = read_rr(data, offset)
        authority.append(auth)
    for _ in range(header.arcount):
        add, offset = read_rr(data, offset)
        additional.append(add)

    dns_packet = Packet(header, questions, answer, authority, additional)
    return dns_packet


def new_response(id, questions, answers):
    header = Header(id=id, qr=1,
                    questions_count=len(questions),
                    ancount=len([answer for answer in answers if answer.rdata != '']))
    response_packet = Packet(header=header,
                             questions=questions,
                             answer_rrs=answers)
    return response_packet


class Cache:
    def __init__(self):
        self.storage = {}

    def add(self, answer):
        key_for_answer = json.dumps([answer.name, answer.type, answer.rr_class])
        if key_for_answer in self.storage:
            self.storage[key_for_answer].append(json.dumps({
                'deadline': time() + answer.ttl,
                'type': answer.type,
                'class': answer.rr_class,
                'rdata': answer.rdata
            }))
        else:
            self.storage[key_for_answer] = [json.dumps({
                'deadline': time() + answer.ttl,
                'type': answer.type,
                'class': answer.rr_class,
                'rdata': answer.rdata
            })]

    def find(self, name, rr_type, rr_class):
        key = json.dumps([name, rr_type, rr_class])
        value = self.storage.get(key)
        if value is None:
            return
        else:
            rrs = []
            for element in value:
                loaded = json.loads(element)
                r_r = ResourceRecord()
                r_r.name = name
                r_r.type = int(loaded['type'])
                r_r.rr_class = int(loaded['class'])
                r_r.ttl = int(int(loaded['deadline']) - time())
                r_r.rdata = loaded['rdata']
                rrs.append(r_r)
            return rrs

    def save(self):
        with open('Cache.json', 'w') as f:
            json.dump(self.storage, f)

    def load(self):
        if not os.path.exists('cache.json'):
            print('There is not cache! New one has been created! (Cache.json)\n')
            with open('Cache.json', 'w') as f:
                json.dump("", f)
            return None
        with open('Cache.json', 'r') as f:
            self.storage = json.load(f)
            print('Cache has been loaded!')

    def delete(self):
        for key in self.storage:
            rrs = self.storage[key]
            for rr in rrs:
                loaded = json.loads(rr)
                if int(loaded['deadline']) < time():
                    rrs.remove(rr)
                    print('Expired record has been deleted!')
        self.storage = {
            k: v for k, v in self.storage.items() if len(v) != 0
        }


def main():
    global forwarder
    forwarder = "8.8.8.8"
    server = Server()
    server.start()


if __name__ == '__main__':
    main()
