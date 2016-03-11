#!/usr/bin/env python3
from __future__ import print_function
import sys, hmac, base64, struct, time, argparse, hashlib
from Crypto.Cipher import AES # PyCrypto from pip
from getpass import getpass
from os.path import expanduser

CONFIG = expanduser("~") + '/.config/otpkeys.enc'

def get_hotp_data(secret, intervals_no):  
  key = base64.b32decode(secret, True)
  msg = struct.pack(">Q", intervals_no)
  h = hmac.new(key, msg, hashlib.sha1).digest()
  o = ord(h[-1:]) & 15
  h = struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff
  return h

def get_hotp_token(secret, digits, intervals_no):
  h = get_hotp_data(secret, intervals_no)
  code = str(h % (10 ** digits))
  return code if len(code) == digits else '0' + code

def get_hotp_token_lang(secret, digits, language, intervals_no):
  h = get_hotp_data(secret, intervals_no)
  code = ""
  for i in range(0, digits):
    code += language[int(h) % len(language)]
    h /= len(language)
  return code

def get_totp_token(secret, digits, seconds=30, language=None):
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
    d_i = hashlib.md5(d_i + pw_bytes + salt).digest()
    d += d_i
  return d[:key_length], d[key_length:key_length+iv_length]

def decrypt(fd, password, key_length=32):
  bs = AES.block_size
  salt = fd.read(bs)[len('Salted__'):]
  key, iv = derive_key_and_iv(password, salt, key_length, bs)
  cipher = AES.new(key, AES.MODE_CBC, iv)
  chunks = next_chunk = b''
  finished = False
  while not finished:
    chunk, next_chunk = next_chunk, cipher.decrypt(fd.read(1024 * bs))
    if len(next_chunk) == 0:
      padding_length = ord(chunk[-1:])
      chunk = chunk[:-padding_length]
      finished = True
    chunks += chunk
  return chunks

def handle_service(svc):
  # Set calculation variables for HOTP token
  digits = 6
  seconds = 30
  language = None
  # Format the secret properly for b32decode
  secret = svc['secret'].replace(' ', '').upper()
  if len(secret) not in [16, 32]:
    target = 16 if (len(secret) < 16) else 32
    while len(secret) < target:
      secret += '='
  if 'digits' in svc:
    digits = svc['digits']
  if 'seconds' in svc:
    seconds = svc['seconds']
  if 'language' in svc:
    language = svc['language']
  result = get_totp_token(secret, digits, seconds, language)
  return result

def print_codes(services):
  # If only one match, make it possible to pipe normally to clipboard manager
  if len(services) == 1:
    service = list(services.keys())[0]
    code, time_left = services[service]
    if not sys.stdout.isatty():
      print('%s (%is) ' % (service, time_left), file=sys.stderr)
    print(code)
  else:
    times = set()
    for service in sorted(services):
      _, time_left = services[service]
      times.add(time_left)
    synched = len(times) == 1
    for service in sorted(services):
      code, time_left = services[service]
      if synched:
        print('%s: %s' % (service, code))
      else:
        print('%s (%is): %s' % (service, time_left, code))
    if synched:
      print('Time left: %i seconds' % (time_left,))

def main(filter_string, password=None):
  if password is None:
    password = getpass(prompt='Password: ', stream=None)
  with open(CONFIG, 'rb') as fd:
    raw = decrypt(fd, password)
  try:
    data = eval(raw.decode('utf-8'))
  except (ValueError, UnicodeDecodeError):
    sys.exit('Bad password')
  results = {}
  for svc in data:
    if filter_string.replace('*','').lower() in svc.lower():
      results[svc] = handle_service(data[svc])
  print_codes(results)
  
if __name__ == "__main__":
  parser = argparse.ArgumentParser(description=
      '''RFC6238-compliant TOTP-token generator''')
  parser.add_argument('filter_string',
      help='Service filter',
      default='*',
      nargs='?')
  parser.add_argument('-p', '--password',
      help='Optionally provide password at the commandline')
  args = parser.parse_args()
  try:
    main(args.filter_string, args.password)
  except KeyboardInterrupt:
    sys.exit('')