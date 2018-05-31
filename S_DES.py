def P10(Init_key):
    temp_key = (Init_key <<2) & int('1000000000',2)   # 3
    temp_key |= (Init_key<<3) & int('0100000000',2)   # 5
    temp_key |= (Init_key>>1) & int('0010000000',2)   # 2
    temp_key |= (Init_key<<3) & int('0001000000',2)   # 7
    temp_key |= (Init_key>>1) & int('0000100000',2)   # 4
    temp_key |= (Init_key<<4) & int('0000010000',2)   # 10
    temp_key |= (Init_key>>6) & int('0000001000',2)   #  1
    temp_key |= (Init_key<<1) & int('0000000100',2)   # 9
    temp_key |= (Init_key>>1) & int('0000000010',2)   # 8
    temp_key |= (Init_key>>4) & int('0000000001',2)   # 6
    return temp_key;

def P8(Init_key):
    temp_key  = (Init_key << 3) & int('0010000000', 2)  # 6
    temp_key |= (Init_key >> 1) & int('0001000000', 2)  # 3
    temp_key |= (Init_key << 2) & int('0000100000', 2)  # 7
    temp_key |= (Init_key >> 2) & int('0000010000', 2)  # 4
    temp_key |= (Init_key << 1) & int('0000001000', 2)  # 8
    temp_key |= (Init_key >> 3) & int('0000000100', 2)  # 5
    temp_key |= (Init_key << 1) & int('0000000010', 2)  # 10
    temp_key |= (Init_key >> 1) & int('0000000001', 2)  # 9
    return temp_key;

def P4(Init_key):
    temp_key  = (Init_key << 1) & int('1000', 2)  # 2
    temp_key |= (Init_key << 2) & int('0100', 2)  # 4
    temp_key |= (Init_key )     & int('0010', 2)  # 3
    temp_key |= (Init_key >> 3) & int('0001', 2)  # 1
    return temp_key;

def IP(ip_data):
    op_data  = (ip_data << 1) & int('10000000', 2)  # 2
    op_data |= (ip_data << 4) & int('01000000', 2)  # 6
    op_data |= (ip_data )     & int('00100000', 2)  # 3
    op_data |= (ip_data >> 3) & int('00010000', 2)  # 1
    op_data |= (ip_data >> 1) & int('00001000', 2)  # 4
    op_data |= (ip_data << 2) & int('00000100', 2)  # 8
    op_data |= (ip_data >> 2) & int('00000010', 2)  # 5
    op_data |= (ip_data >> 1) & int('00000001', 2)  # 7
    return op_data;

def Inv_IP(ip_data):
    op_data  = (ip_data << 3) & int('10000000', 2)  # 4
    op_data |= (ip_data >> 1) & int('01000000', 2)  # 1
    op_data |= (ip_data )     & int('00100000', 2)  # 3
    op_data |= (ip_data << 1) & int('00010000', 2)  # 5
    op_data |= (ip_data << 2) & int('00001000', 2)  # 7
    op_data |= (ip_data >> 4) & int('00000100', 2)  # 2
    op_data |= (ip_data << 1) & int('00000010', 2)  # 8
    op_data |= (ip_data >> 2) & int('00000001', 2)  # 6
    return op_data;

def FK (ip_data,K):
    temp_data = ip_data
    ip_data = ip_data << 4
    op_data  = (ip_data << 3) & int('10000000', 2)  # 4
    op_data |= (ip_data >> 1) & int('01000000', 2)  # 1
    op_data |= (ip_data >> 1) & int('00100000', 2)  # 2
    op_data |= (ip_data >> 1) & int('00010000', 2)  # 3
    op_data |= (ip_data >> 3) & int('00001000', 2)  # 2
    op_data |= (ip_data >> 3) & int('00000100', 2)  # 3
    op_data |= (ip_data >> 3) & int('00000010', 2)  # 4
    op_data |= (ip_data >> 7) & int('00000001', 2)  # 1
    op_data = op_data ^ K
    S0 = [1,0,3,2,3,2,1,0,0,2,1,3,3,1,3,2]
    S1 = [0,1,2,3,2,0,1,3,3,0,1,0,2,1,0,3]
    R = ((op_data >> 6) & int('10',2)) | ((op_data >> 4) & int('01',2))
    C = ((op_data>>5) & int('11',2))
    d1 = S0[(R*4)+C]
    R = ((op_data >> 2) & int('10', 2)) | ((op_data) & int('01', 2))
    C = ((op_data >> 1) & int('11', 2))
    d2 = S1[(R * 4) + C]
    d = (d1 << 2)| d2
    d = P4(d)
    op_data = (temp_data ^ (d << 4))
    return op_data;

def Key_gen (Init_key):
    global K1, K2
    temp_key = P10(Init_key)
    temp_k1 = (temp_key>>4) & int('0000100001',2)
    temp_k1|= (temp_key<<1) & int('1111011110',2)
    K1 = P8(temp_k1)
    temp_k2 =  (temp_k1 >> 3) & int('0001100011', 2)
    temp_k2 |= (temp_k1 << 2) & int('1110011100', 2)
    K2 = P8(temp_k2)
    return;

def DES_encrypt (ptxt,ctxt):
    global P_data, C_data, Init_Vector
    C_data = ''
    P_data = ''
    Pfp = open(ptxt,"rb")
    Cfp = open(ctxt,"wb")
    Key_gen(Init_Key)
    temp_vector = Init_Vector
    data = Pfp.read(1)
    while(data != ''):
        data = ord(data)
        temp_data = format(data,'08b')
        P_data = P_data + ' ' + temp_data
        data = data ^ temp_vector
        data = IP(data)
        data = FK(data,K1)
        data = ((data >> 4) & 0x0F) | ((data << 4) & 0xF0)
        data = FK(data,K2)
        data = Inv_IP(data)
        temp_vector = data
        temp_data = format(data,'08b')
        data = chr(data)
        Cfp.write(data)
        C_data = C_data + ' ' + temp_data
        data = Pfp.read(1)

    Pfp.close()
    Cfp.close()
    return;

def DES_decrypt (ptxt, ctxt):
    global P_data, C_data, Init_Vector
    P_data = ''
    C_data = ''
    Pfp = open(ptxt, "wb")
    Cfp = open(ctxt, "rb")
    Key_gen(Init_Key)
    temp_vector = Init_Vector
    data = Cfp.read(1)
    while (data != ''):
        data = ord(data)
        temp_vector2 = data
        temp_data = format(data,'08b')
        C_data = C_data + ' ' + temp_data
        data = IP(data)
        data = FK(data, K2)
        data = ((data >> 4) & 0x0F) | ((data << 4) & 0xF0)
        data = FK(data, K1)
        data = Inv_IP(data)
        data = data ^ temp_vector
        temp_data = format(data,'08b')
        data = chr(data)
        Pfp.write(data)
        P_data = P_data + ' ' + temp_data
        data = Cfp.read(1)
        temp_vector = temp_vector2

    Pfp.close()
    Cfp.close()
    return;

command_ip = raw_input()
command_ip = command_ip + '  *'
cmd_ptr = 0
while ((command_ip[cmd_ptr] !=' ') or (command_ip[cmd_ptr+1] !='-')  or (command_ip[cmd_ptr+2] !='m') or (command_ip[cmd_ptr+3] !=' ')):
    cmd_ptr = cmd_ptr + 1

cmd_ptr = cmd_ptr + 4
mode = ''
while ((command_ip[cmd_ptr] !=' ') or (command_ip[cmd_ptr+1] !='-')  or (command_ip[cmd_ptr+2] !='k') or (command_ip[cmd_ptr+3] !=' ')):
    mode = mode + command_ip[cmd_ptr]
    cmd_ptr = cmd_ptr + 1

cmd_ptr = cmd_ptr + 4
Init_Key = ''
while ((command_ip[cmd_ptr] !=' ') or (command_ip[cmd_ptr+1] !='-')  or (command_ip[cmd_ptr+2] !='i') or (command_ip[cmd_ptr+3] !=' ')):
    Init_Key = Init_Key + command_ip[cmd_ptr]
    cmd_ptr = cmd_ptr + 1

Init_Key = int(Init_Key,2)

cmd_ptr = cmd_ptr + 4
Init_Vector = ''
while ((command_ip[cmd_ptr] !=' ') or (command_ip[cmd_ptr+1] !='-')  or (command_ip[cmd_ptr+2] !='p') or (command_ip[cmd_ptr+3] !=' ')):
    Init_Vector = Init_Vector + command_ip[cmd_ptr]
    cmd_ptr = cmd_ptr + 1

Init_Vector = int(Init_Vector,2)

cmd_ptr = cmd_ptr + 4
Ptxt_file = ''
while ((command_ip[cmd_ptr] !=' ') or (command_ip[cmd_ptr+1] !='-')  or (command_ip[cmd_ptr+2] !='c') or (command_ip[cmd_ptr+3] !=' ')):
    Ptxt_file = Ptxt_file + command_ip[cmd_ptr]
    cmd_ptr = cmd_ptr + 1

cmd_ptr = cmd_ptr + 4
Ctxt_file = ''
while ((command_ip[cmd_ptr] !=' ') or (command_ip[cmd_ptr+1] != ' ') or (command_ip[cmd_ptr+2] != '*')):
    Ctxt_file = Ctxt_file + command_ip[cmd_ptr]
    cmd_ptr = cmd_ptr + 1

mode = mode.lower()
K1 = 0
K2 = 0
if mode == 'encrypt' :
    DES_encrypt(Ptxt_file,Ctxt_file)
else:
    DES_decrypt(Ptxt_file,Ctxt_file)

K1 = bin(K1)
K2 = bin(K2)

print 'k1=%s' %K1[2:]
print 'k2=%s' %K2[2:]

if mode == 'encrypt':
    print "plaintext= %s" %P_data
    print "ciphertext=%s" % C_data
else:
    print "ciphertext=%s" %C_data
    print "plaintext= %s" % P_data