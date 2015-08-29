import hmac, base64, struct, time, argparse, json, hashlib
from hashlib import md5
from getpass import getpass
from Crypto.Cipher import AES
from Crypto import Random
from os.path import expanduser

CONFIG = expanduser("~") + '/.config/otpkeys.enc'

def get_hotp_data(secret, intervals_no):  
  key = base64.b32decode(secret, True)
  msg = struct.pack(">Q", intervals_no)
  h = hmac.new(key, msg, hashlib.sha1).digest()
  o = ord(h[19]) & 15
  h = struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff
  return h

def get_hotp_token(secret, digits, intervals_no):
  h = get_hotp_data(secret, intervals_no)
  code = str(h % (10 ** digits))
  return code if len(code) == digits else '0' + code

def get_hotp_token_lang(secret, digits, language, intervals_no):
  h = get_hotp_data(secret, intervals_no)
  code = ""
  for i in xrange(0, digits):
    code += language[h % len(language)]
    h /= len(language)
  return code

def get_totp_token(secret, digits, language=None, seconds=30):
  t = int(time.time())
  if language is None:
    code = get_hotp_token(secret, digits, intervals_no=t//seconds)
  else:
    code = get_hotp_token_lang(secret, digits, language, intervals_no=t//seconds)
  return code, -(t % seconds - seconds)

def derive_key_and_iv(password, salt, key_length, iv_length):
  d = d_i = b''
  while len(d) < key_length + iv_length:
    pw_bytes = password.encode('utf-8')
    d_i = md5(d_i + pw_bytes + salt).digest()
    d += d_i
  return d[:key_length], d[key_length:key_length+iv_length]

def decrypt(fd, password, key_length=32):
  bs = AES.block_size
  salt = fd.read(bs)[len('Salted__'):]
  key, iv = derive_key_and_iv(password, salt, key_length, bs)
  cipher = AES.new(key, AES.MODE_CBC, iv)
  next_chunk = ''
  finished = False
  data = ''
  while not finished:
    chunk, next_chunk = next_chunk, cipher.decrypt(fd.read(1024 * bs))
    if len(next_chunk) == 0:
      padding_length = ord(chunk[-1])
      chunk = chunk[:-padding_length]
      finished = True
    data += str(chunk)
  return data

def handle_service(svc, digits=6):
  # Format the secret properly for b32decode later
  secret = svc['secret'].replace(' ', '').upper()
  if len(secret) not in [16, 32]:
    target = 16 if (len(secret) < 16) else 32
    while len(secret) < target:
      secret += '='

  if svc.has_key('digits'):
    digits = svc['digits']
  if svc.has_key('language'):
    result = get_totp_token(secret, digits, svc['language'])
  else:
    result = get_totp_token(secret, digits)
  return result

def main(filter_string, password=None):
  if password is None:
    password = getpass(prompt='Password: ', stream=None)
  with open(CONFIG, 'rb') as fd:
    data = decrypt(fd, password)
  data = json.loads(data)
  for svc in data:
    if filter_string in svc.lower():
      code, time_left = handle_service(data[svc])
      print("%s: %s (%i)" % (svc, code, time_left))
  
if __name__ == "__main__":
  parser = argparse.ArgumentParser(prog='totp generator')
  parser.add_argument('filter_string', help='Service filter')
  parser.add_argument('-p', '--password', help='Optionally provide password at the commandline')
  args = parser.parse_args()
  main(args.filter_string, args.password)