#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
    File:	TOTP_2FAGenerate.py
    Author:	Shixu He
    Email:	heshixu@genomics.cn
    Date:	2019-09-25
    ------
    The origin of 2FA algorithm: https://github.com/bdauvergne/python-oath.git (BSD 3-Clause LICENSE)
    ------
    Version: 1.0
'''

import sys
import os
import base64
import binascii
from urllib.parse import urlparse, parse_qs
import hashlib
import time
import hmac
import struct

OTPAUTH=r"otpauth://totp/username%20username@domain.cn?secret=XXXXXXXXXXXXXXXXXXXX&issuer=ISSUER_NAME"
HOME = os.path.expanduser("~")
CONFIGPATH = HOME + "/.ssh/auto_login.exp"
OTPAUTHPATH = HOME + "/.ssh/TOTP_otpauth_key"

LABEL   =   'label'
TYPE    =    'type'
ALGORITHM = 'algorithm'
DIGITS  =  'digits'
SECRET  =  'secret'
COUNTER = 'counter'
PERIOD  =  'period'
TOTP    =    'totp'
HOTP    =    'hotp'
DRIFT   =   'drift'
ISSUER  = 'issuer'

def fromhex(s):
    return bytes.fromhex(s)
def tohex(bin):
    return binascii.hexlify(bin).decode('ascii')

def lenient_b32decode(data):
    data = data.upper()  # Ensure correct case
    data += ('=' * ((8 - len(data)) % 8))  # Ensure correct padding
    return base64.b32decode(data.encode('ascii'))

def parse_otpauth(otpauth_uri):
    if not otpauth_uri.startswith('otpauth://'):
        raise ValueError('Invalid otpauth URI', otpauth_uri)

    # urlparse in python 2.6 can't handle the otpauth:// scheme, skip it
    parsed_uri = urlparse(otpauth_uri[8:])

    params = dict(((k, v[0]) for k, v in parse_qs(parsed_uri.query).items()))
    params[LABEL] = parsed_uri.path[1:]
    params[TYPE] = parsed_uri.hostname

    if SECRET not in params:
        raise ValueError('Missing secret field in otpauth URI', otpauth_uri)
    try:
        params[SECRET] = tohex(lenient_b32decode(params[SECRET]))
    except TypeError:
        raise ValueError('Invalid base32 encoding of the secret field in '
                         'otpauth URI', otpauth_uri)
    if ALGORITHM in params:
        params[ALGORITHM] = params[ALGORITHM].lower()
        if params[ALGORITHM] not in ('sha1', 'sha256', 'sha512', 'md5'):
            raise ValueError('Invalid value for algorithm field in otpauth '
                             'URI', otpauth_uri)
    else:
        params[ALGORITHM] = 'sha1'
    try:
        params[ALGORITHM] = getattr(hashlib, params[ALGORITHM])
    except AttributeError:
        raise ValueError('Unsupported algorithm %s in othauth URI' %
                         params[ALGORITHM], otpauth_uri)

    for key in (DIGITS, PERIOD, COUNTER):
        try:
            if key in params:
                params[key] = int(params[key])
        except ValueError:
            raise ValueError('Invalid value for field %s in otpauth URI, must '
                             'be a number' % key, otpauth_uri)
    if COUNTER not in params:
        params[COUNTER] = 0 # what else ?
    if DIGITS in params:
        if params[DIGITS] not in (6, 8):
            raise ValueError('Invalid value for field digits in othauth URI, it '
                             'must 6 or 8', otpauth_uri)
    else:
        params[DIGITS] = 6
    if params[TYPE] == HOTP and COUNTER not in params:
        raise ValueError('Missing field counter in otpauth URI, it is '
                         'mandatory with the hotp type', otpauth_uri)
    if params[TYPE] == TOTP and PERIOD not in params:
        params[PERIOD] = 30
    return params

def totp(key, format='dec6', period=30, t=None, hash=hashlib.sha1):
    '''
       Compute a TOTP value as prescribed by OATH specifications.
       :param key:
           the TOTP key given as an hexadecimal string
       :param format:
           the output format, can be:
              - hex, for a variable length hexadecimal format,
              - hex-notrunc, for a 40 characters hexadecimal non-truncated format,
              - dec4, for a 4 characters decimal format,
              - dec6,
              - dec7, or
              - dec8
           it defaults to dec6.
       :param period:
           a positive integer giving the period between changes of the OTP
           value, as seconds, it defaults to 30.
       :param t:
           a positive integer giving the current time as seconds since EPOCH
           (1st January 1970 at 00:00 GMT), if None we use time.time(); it
           defaults to None;
       :param hash:
           the hash module (usually from the hashlib package) to use,
           it defaults to hashlib.sha1.
       :returns:
           a string representation of the OTP value (as instructed by the format parameter).
       :type: str
    '''
    if t is None:
        t = int(time.time())
    else:
        import datetime, calendar
        if isinstance(t, datetime.datetime):
            t = calendar.timegm(t.utctimetuple())
        else:
            t = int(t)
    T = int(t/period)
    return hotp(key, T, format=format, hash=hash)

def truncated_value(h):
    v = h[-1]
    if not isinstance(v, int): v = ord(v) # Python 2.x
    offset = v & 0xF
    (value,) = struct.unpack('>I', h[offset:offset + 4])
    return value & 0x7FFFFFFF

def dec(h,p):
    digits = str(truncated_value(h))
    return digits[-p:].zfill(p)

def int2beint64(i):
    return struct.pack('>Q', int(i))

def __hotp(key, counter, hash=hashlib.sha1):
    bin_counter = int2beint64(counter)
    bin_key = fromhex(key)

    return hmac.new(bin_key, bin_counter, hash).digest()

def hotp(key,counter,format='dec6',hash=hashlib.sha1):
    '''
       Compute a HOTP value as prescribed by RFC4226
       :param key:
           the HOTP secret key given as an hexadecimal string
       :param counter:
           the OTP generation counter
       :param format:
           the output format, can be:
              - hex, for a variable length hexadecimal format,
              - hex-notrunc, for a 40 characters hexadecimal non-truncated format,
              - dec4, for a 4 characters decimal format,
              - dec6,
              - dec7, or
              - dec8
           it defaults to dec6.
       :param hash:
           the hash module (usually from the hashlib package) to use,
           it defaults to hashlib.sha1.
       :returns:
           a string representation of the OTP value (as instructed by the format parameter).
       Examples:
        >>> hotp('343434', 2, format='dec6')
            '791903'
    '''
    bin_hotp = __hotp(key, counter, hash)

    if format == 'dec4':
        return dec(bin_hotp, 4)
    elif format == 'dec6':
        return dec(bin_hotp, 6)
    elif format == 'dec7':
        return dec(bin_hotp, 7)
    elif format == 'dec8':
        return dec(bin_hotp, 8)
    elif format == 'hex':
        return '%x' % truncated_value(bin_hotp)
    elif format == 'hex-notrunc':
        return tohex(bin_hotp)
    elif format == 'bin':
        return bin_hotp
    elif format == 'dec':
        return str(truncated_value(bin_hotp))
    else:
        raise ValueError('unknown format')


def generate(otpauth_uri):
    parsed_otpauth_uri = parse_otpauth(otpauth_uri)
    format = 'dec%s' % parsed_otpauth_uri[DIGITS]
    hash = parsed_otpauth_uri[ALGORITHM]
    secret = parsed_otpauth_uri[SECRET]
    state = {}
    if parsed_otpauth_uri[TYPE] == HOTP:
        if COUNTER not in state:
            state[COUNTER] = parsed_otpauth_uri[COUNTER]
        otp = hotp(secret, state[COUNTER], format=format, hash=hash)
        state[COUNTER] += 1
        return otp
    elif parsed_otpauth_uri[TYPE] == TOTP:
        period = parsed_otpauth_uri[PERIOD]
        return totp(secret, format=format,
                         period=period,
                         hash=hash, t=None)
    else:
        raise NotImplementedError(parsed_otpauth_uri[TYPE])

def configFile(filepath):
    with open(filepath, "wt") as _ot:
        _ot.write('''#!/usr/bin/expect -f
set username [lindex $argv 0]
set serverip [lindex $argv 1]
set vcode [lindex $argv 2]
set passwd "password"
set logincount 0
set timeout -1
spawn ssh $username@$serverip
expect {
    "*assword:" {
        if { $logincount < 1 } {
            send "$passwd\\r"; set logincount 2; exp_continue
        } else {
            send_user "\\n\\nYou encounter loop login. Please make sure that the passwd and outh-key are correct.\\n"; send \\x03;
        }
    }
    "*erification*code" {send "$vcode\\r"; exp_continue}
    "*login*"
}
interact
exit
''')


def usage():
#    print('''======================================================================
#-> python3 TOTP_2FAGenerate.py config
#
#This will generate:
#    auto_login file: ~/.ssh/auto_login.exp
#    otpaupath file:  ~/.ssh/TOTP_otpauth_key
#
#======================================================================
#Generate 2FA code: 
#-> python3 TOTP_2FAGenerate.py code <username> <serverip> <passwd>
#
#======================================================================
#TOTP-2FA ssh auto-login method: (utilizing linux "expect" program)
#-> expect -f ~/.ssh/auto_login.exp $(python3 TOTP_2FAGenerate.py code <username> <serverip> <passwd>)
#
#Check your otpauth key or try the command again if fail to login as the algorithm is dependent on system time.
#
#======================================================================
#Other methods:
#Add "ControlMaster, ControlPath, ControlPersist" configure items to specific host in your ~/.ssh/config file. Which will build a special tunnel #that can be re-used, then consequent ssh will use the same tunnel without login. Then you can use:
#-> if [ -S ~/.ssh/master-user@serverip:port ]; then ssh user@serverip:port; else expect xxxxxxxx...; fi # this will check the existed ssh tunnel #when you set ControlMaster in .ssh/config file.
    print('''======================================================================
Support system:
MacOS, Linux, Windows WSL
Windows 的各种终端工具是自带的弹窗验证, 暂时无解.

用法说明: 
1. 先用 python3 TOTP_2FAGenerate.py config 命令生成所需文件.
2. 用离线二维码扫描器 (离线的安全一些，最好是手机自带的那种, 微信的扫一扫也可以) 扫个人专属的两步验证二维码(就是添加Authenticator时扫的那个).
3. 扫描完后选择复制内容/复制链接或者分享到记事本等, 以获取相应的文本. 当前支持的二维码内容是 otpauth://totp 开头的模式. 
    (格式: otpauth://totp/username%20username@domain.cn?secret=XXXXXXXXXXXXXXXXXXXXXXX&issuer=ISSUER_NAME)
4. 将文本内容贴到 ~/.ssh/TOTP_otpauth_key 中, 然后就可以用最开始生成的exp脚本实现免密登录. 建议添加到 bashrc 的快捷命令中. 
5. 在 ~/.ssh/auto_login.exp 中修改自己的集群登录密码.
6. 免密登录命令: expect -f ~/.ssh/auto_login.exp $(python3 TOTP_2FAGenerate.py code <username> <serverip>)

如果登录失败请检查 otpauth 内容是否正确, 也可以再登录一次或者等一会再尝试, 因为当前的 2FA 是时间相关的算法.

辅助方法: 在 ~/.ssh/config 中为指定 host 添加 "ControlMaster, ControlPath, ControlPersist" 参数，可以实现 ssh 通道的复用，登录一次后，后续的就不需要再登录。
''')


if __name__ == "__main__":
    if (len(sys.argv) < 2):
        usage()
    elif (sys.argv[1] == "code"):
        if (len(sys.argv) != 4):
            usage()
            sys.exit(0)
        with open(OTPAUTHPATH, "rt") as _otpa:
            OTPAUTH = _otpa.readline().rstrip()
        #print("{0} {1} {2} {3}".format(sys.argv[2], sys.argv[3], sys.argv[4], generate(OTPAUTH)))
        print("{0} {1} {2}".format(sys.argv[2], sys.argv[3], generate(OTPAUTH)))
    elif (sys.argv[1] == "config"):
        if len(sys.argv) == 2:
            configFile(CONFIGPATH)
            with open(OTPAUTHPATH, "wt") as _oth:
                _oth.write(OTPAUTH)
            print("\nFile created:\nauto login file: ~/.ssh/auto_login.exp\nsecret key file: ~/.ssh/TOTP_otpauth_key\n")
        else:
            usage()
    elif (sys.argv[1] == "--help" or sys.argv[1] == "-h"):
        usage()
