import base64
import hashlib
import json
import math
import time
import urllib.parse
import urllib.request

from typing import Any, Dict, Tuple

SECRET_FILE_PATH = "~/secret.json"
SCOPES = "https://www.googleapis.com/auth/cloud-platform"
DEFAULT_TOKEN_AUDIENCE = "https://oauth2.googleapis.com/token"
RSA_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

secret : Dict[str, Any] = json.loads(open(SECRET_FILE_PATH, "r").read())

jwt_header : Dict[str, Any] = {}
jwt_header["alg"] = "RS256"
jwt_header["typ"] = "JWT"
jwt_header["kid"] = secret.get("private_key_id", None)
jwt_header_str : str = json.dumps(jwt_header)

jwt_claim_set : Dict[str, Any] = {}
jwt_claim_set["iss"] = secret.get("client_email")
jwt_claim_set["scope"] = SCOPES
jwt_claim_set["aud"] = secret.get("token_uri", DEFAULT_TOKEN_AUDIENCE)
jwt_claim_set["iat"] = int(time.time())
jwt_claim_set["exp"] = jwt_claim_set["iat"] + 3600
jwt_claim_str : str = json.dumps(jwt_claim_set)

base64_encoded_jwt_header_str : str = base64.urlsafe_b64encode(bytes(jwt_header_str, "utf-8")).decode("utf-8").rstrip("=")
base64_encoded_jwt_claim_str  : str = base64.urlsafe_b64encode(bytes(jwt_claim_str, "utf-8")).decode("utf-8").rstrip("=")

string_to_be_signed : str   = base64_encoded_jwt_header_str + "." + base64_encoded_jwt_claim_str

def _convert_PEM_to_DER(key: str) -> bytes:

    concat_key_string = ''.join(i for i in key.splitlines() if not i.startswith("-----"))
    key_bytes = base64.b64decode(concat_key_string)

    return key_bytes

def _parse_DER_length(der_bytes: bytes, offset: int) -> Tuple[int, int]:

    first = der_bytes[offset]

    if first < 0x80:

        return first, offset + 1
    
    num_bytes = first & 0x7F
    length = int.from_bytes(der_bytes[offset + 1 : offset + 1 + num_bytes], "big")

    return length, offset + 1 + num_bytes

def _parse_DER_element(der_bytes: bytes, offset: int) -> Tuple[int, bytes, int]:

    tag = der_bytes[offset]

    length, offset = _parse_DER_length(der_bytes, offset + 1)
    value =  der_bytes[offset : offset + length]

    return tag, value, offset + length

def _parse_DER_integer(der_bytes: bytes, offset: int) -> Tuple[int, int]:

    tag, value, offset = _parse_DER_element(der_bytes, offset)

    if tag != 0x02:
        raise ValueError("Expected INTEGER tag")
    
    return int.from_bytes(value, "big"), offset

def _parse_ASN1_private_key(der_bytes: bytes) -> dict[str, int]:

    tag, pkcs8_body, offset = _parse_DER_element(der_bytes, 0)

    if tag != 0x30:
        raise ValueError("Expected SEQUENCE tag for PKCS#8")
    
    _version, offset = _parse_DER_integer(pkcs8_body, 0)

    tag, _alg_identifier, offset = _parse_DER_element(pkcs8_body, offset)

    if tag != 0x30:
        raise ValueError("Expected SEQUENCE tag for Algorithm Identifier")
    
    tag, pkcs1_wrapped, offset = _parse_DER_element(pkcs8_body, offset)

    if tag != 0x04:
        raise ValueError("Expected OCTET STRING tag for PKCS#1 Wrapped Key")
    
    tag, pkcs1_body, _ = _parse_DER_element(pkcs1_wrapped, 0)

    if tag != 0x30:
        raise ValueError("Expected SEQUENCE tag for PKCS#1 body")
    
    offset = 0
    fields : dict[str, int] = {}
    names : list[str] = ["version", "n", "e", "d", "p", "q", "dp", "dq", "qinv"]

    for name in names:
        value, offset = _parse_DER_integer(pkcs1_body, offset)
        fields[name] = value

    return fields

def _EMSA_PKCS1_V1_5_ENCODE(message: bytes, k: int) -> bytes:

    hash_digest = hashlib.sha256(message).digest()
    t = RSA_SHA256_PREFIX + hash_digest

    if k < len(t) + 11:
        raise ValueError("Intended encoded message length too short")
    
    ps = bytes([0xFF] * (k- len(t) - 3))
    em = bytes([0x00]) + bytes([0x01]) + ps + bytes([0x00]) + t

    return em

def _OS2IP(x: bytes) -> int:
    return int.from_bytes(x, "big")

def _RSASP1(K: Tuple[int, int], m: int) -> int:

    assert len(K) == 2, "For now, only (n,d) key is accepted"

    n, d = K
    
    if not 0 <= m <= n-1:
        raise ValueError("Representative Message m is not between 0 and n-1")
    
    s = pow(m, d, n)

    return s

def _I2OSP(x: int, xLen: int) -> bytes:

    if x > pow(256, xLen):
        raise ValueError("Integer too large")
    
    return int.to_bytes(x, xLen, "big")

def RSASSA_PKCS1_V1_5_SIGN(private_key: str, message: bytes) -> bytes:

    private_key_bytes = _convert_PEM_to_DER(private_key)
    fields = _parse_ASN1_private_key(private_key_bytes)

    num_bits = fields.get("n", 0).bit_length()

    assert num_bits > 0, "Expected num_bits > 0"

    k = math.ceil(num_bits / 8)

    em = _EMSA_PKCS1_V1_5_ENCODE(message, k)

    assert len(em) == k, "Encoded message length doesn't match expected length"

    m = _OS2IP(em)
    s = _RSASP1((fields.get("n", 0), fields.get("d", 0)), m)

    return _I2OSP(s, k)

signed_bytes = RSASSA_PKCS1_V1_5_SIGN(secret.get("private_key", ""), string_to_be_signed.encode("utf-8"))

base64_encoded_jwt_signature_string = base64.urlsafe_b64encode(signed_bytes).decode("utf-8").rstrip("=")

jwt = string_to_be_signed + "." + base64_encoded_jwt_signature_string

request_params = {
    "grant_type" : "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "assertion" : jwt
}

data = urllib.parse.urlencode(request_params).encode("utf-8")
req = urllib.request.Request(jwt_claim_set["aud"], data = data, method = "POST")

with urllib.request.urlopen(req) as response:
    status_code = response.status
    response = json.loads(response.read().decode("utf-8"))

auth_token = response.get("access_token")

print(auth_token)
