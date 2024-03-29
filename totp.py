#!/usr/bin/env python3
from __future__ import print_function, division
import sys, hmac, base64, struct, argparse, hashlib, re, time, math
from Crypto.Cipher import AES # PyCrypto from pip
from getpass import getpass
from os.path import expanduser

SECRETS = expanduser('~/.config/otpkeys.enc')
EPOCH = int(time.time())
B32CHARS = re.compile(r'[^A-Z2-7]')

def hotp_data(secret, intervals_no):
  target = math.ceil(len(secret)/8)*8
  secret += '='*int(target-len(secret))
  key = base64.b32decode(secret)
  msg = struct.pack('>Q', intervals_no)
  h = hmac.new(key, msg, hashlib.sha1).digest()
  o = ord(h[-1:]) & 15
  h = struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff
  return h

def totp_code(secret, digits, seconds=30, language=None):
  h = hotp_data(secret, EPOCH//seconds)
  code = str('')
  if language is None:
    c = str(h % (10 ** digits))
    code += '0' * (digits - len(c)) + c
  else:
    for i in range(0, digits):
      code += language[int(h) % len(language)]
      h /= len(language)
  return code, -(EPOCH % seconds - seconds)

def handle_service(svc):
  # Set calculation variables for HOTP token
  digits = 6
  seconds = 30
  language = None
  # Format the secret properly for b32decode
  secret = B32CHARS.sub('', svc['secret'].upper())
  if 'digits' in svc:
    digits = svc['digits']
  if 'seconds' in svc:
    seconds = svc['seconds']
  if 'language' in svc:
    language = svc['language']
  result = totp_code(secret, digits, seconds, language)
  return result

def print_codes(services):
  # If only one match, make it possible to pipe normally to clipboard manager
  if len(services) == 1 and not sys.stdout.isatty():
    service = list(services.keys())[0]
    code, time_left = services[service]
    print('%s (%is) ' % (service, time_left), end='', file=sys.stderr)
    sys.stderr.flush()
    print(code, end='')
    sys.stdout.flush()
    # print('', file=sys.stderr)
  else:
    times = {}
    longest = {}
    for service in services:
      _, time_left = services[service]
      if time_left not in longest:
        longest[time_left] = 0
      if len(service) > longest[time_left]:
        longest[time_left] = len(service)
      if time_left not in times:
        times[time_left] = []
      times[time_left].append(service)
    first = True
    for time in sorted(times):
      multiple_services = len(times[time]) > 1
      if multiple_services:
        if first:
          first = False
        else:
          print('')
        print('Time left: %i seconds' % time_left)
      for service in sorted(times[time]):
        code, _ = services[service]
        if multiple_services:
          spaces = longest[time] - len(service) + 1
          print('%s%s %s' % (' '*spaces, service, code))
        else:
          print('%s (%is): %s' % (service, time, code))

def derive_key_and_iv(password, salt, key_length, iv_length):
  pw_bytes = password.encode('utf-8')
  d = hashlib.pbkdf2_hmac('sha256', pw_bytes, salt, 10000, 48)
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

def fuzzysearch(needle, haystack):
  nlen = len(needle)
  hlen = len(haystack)
  if nlen > hlen or hlen == 0:
    return False
  if nlen == hlen:
    return needle == haystack
  if nlen == 0:
    return True
  pos = haystack.find(needle[0])
  return fuzzysearch(needle[1:], haystack[pos+1:]) if pos >= 0 else False

def main(filter_string, password=None):
  if password is None:
    password = getpass(prompt='Password: ', stream=None)
    print('', end='\033[F\033[K', file=sys.stderr)
    sys.stderr.flush()
  with open(SECRETS, 'rb') as fd:
    raw = decrypt(fd, password)
  try:
    data = eval(raw.decode('utf-8'))
  except (ValueError, UnicodeDecodeError):
    sys.exit('Bad password')
  results = {}
  for svc in data:
    if fuzzysearch(filter_string.replace('*','').lower(), svc.lower()):
      if 'secret' in data[svc]:
        results[svc] = handle_service(data[svc])
  print_codes(results)

if __name__ == '__main__':
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
