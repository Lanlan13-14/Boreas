"""Independent, bounded parsers for candidate E2E and RootAuthorization bindings.

This module intentionally uses only Python's standard library. It validates byte
structure and policy fields, never cryptographic signatures or DER key validity.
"""
class BindingError(ValueError):
    def __init__(self, category):
        self.category = category
        super().__init__(category)


def parse_e2e_record(raw):
    if len(raw) < 2:
        raise BindingError("e2e_truncated_length")
    n = int.from_bytes(raw[:2], "big")
    if n != 73:
        raise BindingError("e2e_bad_length")
    if len(raw) != 75:
        raise BindingError("e2e_truncated_or_trailing")
    b = raw[2:]
    if b[:4] != b"BE2E": raise BindingError("e2e_magic")
    if b[4] != 1: raise BindingError("e2e_version")
    if b[5] not in (1, 2): raise BindingError("e2e_message_type")
    net=b[6:22]; ino=int.from_bytes(b[22:24],"big"); igen=int.from_bytes(b[24:32],"big"); ir=b[32]
    ano=int.from_bytes(b[33:35],"big"); agen=int.from_bytes(b[35:43],"big"); ar=b[43]
    cid=b[44:60]; mode=b[60]; suite=b[61]; opener=int.from_bytes(b[62:64],"big"); hops=b[64]
    caps=int.from_bytes(b[65:73],"big")
    if net == bytes(16): raise BindingError("e2e_zero_network")
    if not ino or not ano or ino >= ano: raise BindingError("e2e_endpoint_order_or_id")
    if not igen or not agen: raise BindingError("e2e_generation")
    if ir not in (1,2,3) or ar not in (1,2,3): raise BindingError("e2e_role")
    if cid == bytes(16): raise BindingError("e2e_zero_circuit")
    if mode != 1: raise BindingError("e2e_mode")
    if suite != 1: raise BindingError("e2e_suite")
    if opener not in (ino, ano): raise BindingError("e2e_opener")
    if not 1 <= hops <= 8: raise BindingError("e2e_path_hops")
    if caps: raise BindingError("e2e_capabilities")
    return {"message_type":b[5],"net_id":net.hex(),"initiator_node_id":ino,"initiator_generation":igen,"initiator_role":ir,"acceptor_node_id":ano,"acceptor_generation":agen,"acceptor_role":ar,"circuit_id":cid.hex(),"mode":mode,"suite":suite,"opener_node_id":opener,"path_hops":hops,"capabilities":caps}


class _CBOR:
    def __init__(self, b): self.b=b
    def value(self, p=0, depth=0):
        if depth>8 or p>=len(self.b): raise BindingError("root_cbor_truncated_or_depth")
        start=p; h=self.b[p]; p+=1; major=h>>5; ai=h&31
        if ai<24: n=ai
        elif ai in (24,25,26,27):
            size={24:1,25:2,26:4,27:8}[ai]
            if p+size>len(self.b): raise BindingError("root_cbor_truncated")
            n=int.from_bytes(self.b[p:p+size],"big"); p+=size
            if n < {24:24,25:256,26:65536,27:4294967296}[ai]: raise BindingError("root_cbor_noncanonical")
        else: raise BindingError("root_cbor_indefinite_or_reserved")
        if major==0: return n,p
        if major==2:
            if p+n>len(self.b): raise BindingError("root_cbor_truncated")
            return self.b[p:p+n],p+n
        if major in (4,5):
            if major == 4 and n>256: raise BindingError("root_scope_too_large")
            if major == 5 and n>16: raise BindingError("root_map_too_large")
            out=[]
            for _ in range(n*(2 if major==5 else 1)):
                v,p=self.value(p,depth+1); out.append(v)
            if major==4:return out,p
            if n>16: raise BindingError("root_map_too_large")
            pairs=list(zip(out[::2],out[1::2]))
            if any(not _plain_uint(k) for k,v in pairs) or any(pairs[i-1][0]>=pairs[i][0] for i in range(1,len(pairs))): raise BindingError("root_map_keys")
            return dict(pairs),p
        if major==7 and ai==20:return False,p
        if major==7 and ai==21:return True,p
        raise BindingError("root_cbor_type")


def _uint(x):
    if not _plain_uint(x): raise BindingError("root_field_type")
    return x

def _plain_uint(x):
    return isinstance(x, int) and not isinstance(x, bool)

def _bytes(x):
    if not isinstance(x,bytes): raise BindingError("root_field_type")
    return x

def _scope(purpose, raw):
    v,end=_CBOR(raw).value()
    if end!=len(raw): raise BindingError("root_scope_trailing")
    if purpose==1:
        if not isinstance(v,dict) or set(v)!={0,1} or not isinstance(v[0],list) or not isinstance(v[1],list): raise BindingError("root_scope_shape")
        roles=v[0]; cores=v[1]
        if not roles or len(roles)>3 or any(not _plain_uint(x) or x not in (1,2,3) for x in roles) or roles!=sorted(set(roles)): raise BindingError("root_scope_roles")
        if not cores or len(cores)>16 or any(not _plain_uint(x) or not 1<=x<=16 for x in cores) or cores!=sorted(set(cores)): raise BindingError("root_scope_cores")
    elif purpose==2:
        if not isinstance(v,list) or not v or len(v)>256: raise BindingError("root_scope_shape")
        last=None
        for item in v:
            if not isinstance(item,list) or len(item)!=2 or not isinstance(item[0],bytes) or len(item[0]) not in (4,16) or not _plain_uint(item[1]): raise BindingError("root_scope_prefix")
            addr,p=item; maxp=len(addr)*8
            if p<0 or p>maxp or int.from_bytes(addr,"big") & ((1 << (maxp-p))-1 if p<maxp else 0): raise BindingError("root_scope_prefix")
            key=(addr,p)
            if last is not None and key<=last: raise BindingError("root_scope_order")
            last=key
    elif purpose==3:
        if v!={}: raise BindingError("root_scope_shape")
    elif purpose==4:
        if not _plain_uint(v) or not 1<=v<=16: raise BindingError("root_scope_core")
    else: raise BindingError("root_purpose")
    return v


def parse_root_authorization(raw):
    if len(raw)>16384: raise BindingError("root_too_large")
    value,end=_CBOR(raw).value()
    if end!=len(raw): raise BindingError("root_trailing")
    if not isinstance(value,dict) or list(value)!=list(range(14)): raise BindingError("root_fields")
    if _uint(value[0])!=1: raise BindingError("root_version")
    net=_bytes(value[1]); keyid=_bytes(value[2]); gen=_uint(value[3]); purpose=_uint(value[4])
    if purpose not in (1,2,3,4): raise BindingError("root_purpose")
    ed=_bytes(value[5]); param=_uint(value[6]); pq=_bytes(value[7]); scope_raw=_bytes(value[8]); before=_uint(value[9]); expiry=_uint(value[10]); depth=_uint(value[11]); delegate=value[12]
    if not isinstance(value[13],list) or value[13]: raise BindingError("root_extensions")
    if len(net)!=16 or not keyid or len(keyid)>64 or gen==0 or param not in (1,2) or not ed or len(ed)>4096 or not pq or len(pq)>4096: raise BindingError("root_field_bounds")
    if before>=expiry: raise BindingError("root_time_order")
    if depth!=1: raise BindingError("root_chain_depth")
    if delegate is not False: raise BindingError("root_delegation")
    scope=_scope(purpose,scope_raw)
    return {"net_id":net.hex(),"issuer_key_id":keyid.hex(),"issuer_generation":gen,"purpose":purpose,"ed25519_der_hex":ed.hex(),"mldsa_parameter_set":param,"mldsa_der_hex":pq.hex(),"scope":scope,"not_before_us":before,"expires_us":expiry,"chain_depth":depth,"may_delegate":False}
