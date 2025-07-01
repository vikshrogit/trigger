import json
from requests import  get, Session
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from bs4 import BeautifulSoup
import re
import os
import sys

def to_numbers(hex_str):
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def to_hex(byte_list):
    return ''.join(f"{b:02x}" for b in byte_list)

class Trigger:
    url:str=''
    token:str=''
    session:Session=None
    cookies:dict=None
    ua:str=''
    cookie_file:str = '.cache/cookies.json'

    def __init__(self,*args,**kwargs):
        if len(args)>0:
            self.url = args[0]
            self.token = args[1] if len(args)>1 else None
            self.session = args[2] if len(args)>2 else Session()
            self.cookie_file = args[3] if len(args)>3 else '.cache/cookies.json'
        for k,v in kwargs.items():
            setattr(self,k,v)
        if self.session is None:
            self.session = Session()
        if os.path.exists(self.cookie_file):
            with open(self.cookie_file,"r") as f:
                self.cookies = json.load(f)
                f.close()
        else:
            os.makedirs(os.path.dirname(self.cookie_file),exist_ok=True)
        if self.cookies!=None:
            self.session.cookies.update(self.cookies)


    def getCookie(self, a, b, c):
        a = to_numbers(a)  # key
        b = to_numbers(b)  # iv
        c = to_numbers(c)  # cipher text

        key = bytes(a)
        iv = bytes(b)
        ciphertext = bytes(c)

        # Decrypt using AES-CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        # Safe way to handle padding: try decoding or slice if known
        try:
            decrypted = unpad(plaintext, AES.block_size)
        except ValueError:
            # If no padding used, use raw
            decrypted = plaintext.rstrip(b"\x00")  # some JS encryption pads with 0x00
        self.cookies = dict()
        self.cookies['__test'] = to_hex(decrypted)
        self.session.cookies.update(self.cookies)
        os.makedirs(os.path.dirname(self.cookie_file), exist_ok=True)
        with open(self.cookie_file,"w+") as f:
            json.dump(self.cookies,f)
            f.close()

    def bypass(self,response):
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check if aes.js is used
        aes_js_found = any(script.get('src') == '/aes.js' for script in soup.find_all('script'))
        if not aes_js_found:
            return False
        else:
            # Find inline script with toNumbers(...)
            script_tags = soup.find_all('script')
            script_text = ''
            for tag in script_tags:
                if tag.string and 'toNumbers' in tag.string:
                    script_text = tag.string
                    break

            if not script_text:
                print("AES script not found.")
                return None

            # Extract toNumbers(...) values using regex
            pattern = re.compile(r'toNumbers\("([0-9a-fA-F]+)"\)')
            matches = pattern.findall(script_text)
            if len(matches) < 3:
                print("Not enough parameters for decryption.")
                return None

            self.getCookie(*matches[:3])
            return True


    def trigger(self):
        if not self.url:
            raise Exception("No URL provided.")
        if self.session is not None:
            if self.token is not None:
                self.session.headers.update({'Authorization': 'Bearer '+self.token})

            # Chrome-like headers
            self.session.headers.update({
                "User-Agent": self.ua if self.ua else (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,image/apng,*/*;q=0.8,"
                    "application/signed-exchange;v=b3;q=0.7"
                ),
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document"
            })
            try:
                res = self.session.get(self.url)
                if self.bypass(res):
                    raise Exception("Storing Cache for cookies. Then Retrying...")
            except Exception as e:
                print(e)
                res = self.session.get(self.url)
            if res.status_code != 200:
                raise Exception(res.text)
            #print(res.headers)
            #print(res.content)
            return res.content.decode()
        return None


def parse_custom_args(argv):
    args_dict = {}
    args_list = []
    if argv and argv[0].endswith('.py'):
        argv = argv[1:]
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("--") or (arg.startswith("-") and len(arg) > 1):
            # Ensure there's a next value for the key
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                args_dict[arg.lstrip("-")] = argv[i + 1]
                i += 2
            else:
                args_dict[arg.lstrip("-")] = True  # flag with no value
                i += 1
        else:
            args_list.append(arg)
            i += 1

    return args_dict, args_list


def main():
    args_dict, args_list = parse_custom_args(sys.argv)
    if not len(args_list)>0 and not len(args_dict)>0:
        print("No arguments provided.")
        sys.exit(1)
    if "u" in args_dict:
        args_dict['url'] = args_dict['u']
    if "t" in args_dict:
        args_dict['token'] = args_dict['t']
    trigger = Trigger(*args_list, **args_dict)
    response = trigger.trigger()
    print(response)
if __name__ == '__main__':
    main()