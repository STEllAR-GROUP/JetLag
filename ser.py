import pickle
import base64

def ser(obj):
    return base64.b64encode(pickle.dumps(obj)).decode()

def deser(s):
    return pickle.loads(base64.b64decode(s.encode()))
