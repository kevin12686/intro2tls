import sys, os

sys.argv.pop(0)
if len(sys.argv) != 5:
    print('Wrong Input')
    print('Python <Python Script> <c2s> <s2c> <RSA Key> <ClientPlaintxt> <ServerPlaintxt>')
    exit()

for index in range(0, 3):
    if os.path.exists(sys.argv[index]) == False:
        print('Files not found !!')
        exit()

print('Files inputed.')
pc2s = sys.argv[0]
ps2c = sys.argv[1]
pkey = sys.argv[2]
pcpt = sys.argv[3]
pspt = sys.argv[4]

#define
mac_key_length = 20
enc_key_length = 16

def enum(**enums):
    return type('Enum', (), enums)

ContentType = enum(change_cipher_spec = 20,
                   alert = 21,
                   handshake = 22, application_data = 23)

HandshakeType = enum(hello_request = 0,
                     client_hello = 1,
                     server_hello = 2,
                     certificate = 11,
                     server_key_exchange = 12,
                     certificate_request = 13,
                     server_hello_done = 14,
                     certificate_verity = 15,
                     client_key_exchange = 16,
                     finished = 20)

def Command(command, stdin = None):
    from subprocess import Popen, PIPE
    sub = Popen(command, stdin = PIPE, stdout = PIPE, stderr = PIPE)
    stdout, stderr = sub.communicate(stdin)
    return stdout, stderr, sub.returncode

#both input and output are binary
def tls_prf(PremasterSecret, Lable, seed, n_bytes):
    import hmac
    last = Lable + seed
    result = b''
    while(len(result) < n_bytes):
        last = hmac.new(PremasterSecret, last, 'sha256').digest()
        result += hmac.new(PremasterSecret, last + Lable + seed,'sha256').digest()
    return result[:n_bytes]

#chipertext is binary
def rsaDecrypt(chipertext, keyfile):
    stdout, stderr, returncode = Command(['openssl', 'rsautl', '-decrypt','-inkey', keyfile], chipertext)
    return stdout

#all input are binary
def aes128cbc_decrypt(SecretKey, IniVector, Ciphertext):
    stdout, stdeer, returncode = Command(['openssl', 'enc', '-aes-128-cbc', '-d', '-nopad','-K',
                                          SecretKey.hex(), '-iv', IniVector.hex()], stdin=Ciphertext)
    return stdout

def Handshake_getRandom(code):
    return code[4:68]

def ClientKeyExchange_getPremasterSecert(code):
    return code[4:]


def HandshakeMsg(code):
    Type = int(code[:2], 16)
    Length = int(code[2:8], 16)
    Detail = code[8:8 + Length * 2]
    return Type ,Detail;

def C2S(code):
    ClientRandom = ''
    Premasterkey = ''
    ApplicationData = ''
    while(len(code) != 0):
        try:
            Type = int(code[:2], 16)
            #Version = code[2:6]
            Length = int(code[6:10], 16)
            Detail = code[10:10 + Length * 2]
            if Type == ContentType.handshake:
                Htype, val = HandshakeMsg(Detail)
                if Htype == HandshakeType.client_hello:
                    ClientRandom += Handshake_getRandom(val)
                elif Htype == HandshakeType.client_key_exchange:
                    Premasterkey += ClientKeyExchange_getPremasterSecert(val)
            elif Type == ContentType.application_data:
                ApplicationData += Detail
            code = code[10 + Length * 2:]
        except:
            break
    return ClientRandom, Premasterkey, ApplicationData

def S2C(code):
    ServerRandom = ''
    ApplicationData = ''
    while(len(code) != 0):
        try:
            Type = int(code[:2], 16)
            #Version = code[2:6]
            Length = int(code[6:10], 16)
            Detail = code[10:10 + Length * 2]
            if Type == ContentType.handshake:
                Htype, val = HandshakeMsg(Detail)
                if Htype == HandshakeType.server_hello:
                    ServerRandom += Handshake_getRandom(val)
            elif Type == ContentType.application_data:
                ApplicationData += Detail
            code = code[10 + Length * 2:]
        except:
            break
    return ServerRandom, ApplicationData


#Main

fc2s = open(pc2s, 'rb')
fs2c = open(ps2c, 'rb')
c2s = fc2s.read().hex()
s2c = fs2c.read().hex()
fc2s.close()
fs2c.close()

ClientRandom, PremasterSecret, ClientApplicationData = C2S(c2s)
ServerRandom, ServerApplicationData = S2C(s2c)

if (ClientRandom == '' or PremasterSecret == '' or ClientApplicationData == '' or
            ServerRandom == '' or ServerApplicationData == ''):
    print('Error')
    exit()

PremasterSecret = rsaDecrypt(bytes.fromhex(PremasterSecret), pkey).hex()
MasterSecret = tls_prf(bytes.fromhex(PremasterSecret), b'master secret',
                       bytes.fromhex(ClientRandom + ServerRandom), 48).hex()
KeyBlock = tls_prf(bytes.fromhex(MasterSecret), b'key expansion', bytes.fromhex(ServerRandom + ClientRandom), 72)
ServerWriteKey = KeyBlock[mac_key_length * 2 + enc_key_length:mac_key_length * 2 + enc_key_length * 2].hex()
ClientWriteKey = KeyBlock[mac_key_length * 2:mac_key_length * 2 + enc_key_length].hex()
ServerPlaintext = aes128cbc_decrypt(bytes.fromhex(ServerWriteKey), bytes.fromhex(ServerApplicationData)[:16],
                                    bytes.fromhex(ServerApplicationData)[16:])
ClientPlaintext = aes128cbc_decrypt(bytes.fromhex(ClientWriteKey), bytes.fromhex(ClientApplicationData)[:16],
                                    bytes.fromhex(ClientApplicationData)[16:])

ServerPlaintext = ServerPlaintext[:-(21 + int(ServerPlaintext.hex()[-2:], 16))]
ClientPlaintext = ClientPlaintext[:-(21 + int(ClientPlaintext.hex()[-2:], 16))]

output = open(pspt, 'wb')
output.write(ServerPlaintext)
output.flush()
output.close()

output = open(pcpt, 'wb')
output.write(ClientPlaintext)
output.flush()
output.close()

print('\'' + pspt + '\' \'' +  pcpt + '\' Outputed.')
