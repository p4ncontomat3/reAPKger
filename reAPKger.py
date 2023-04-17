#!/usr/bin/python3
import subprocess
import os
import sys

def check_dependencies():
    dependencies = ['apktool', 'jarsigner', 'apksigner', 'zipalign']
    for dep in dependencies:
        try:
            subprocess.check_output(['which', dep])
        except subprocess.CalledProcessError:
            print(f"[*] Error: {dep} is not installed on the system.")
            sys.exit(1)

def check_signature_scheme(APK):
    command = 'apksigner verify -v {} | grep -i "APK" | grep -i "true"'.format(APK)
    try:
        output = subprocess.check_output(command, shell=True)
        scheme = output.decode().strip().split('\n')
        for i in range(0,len(scheme)):
            if '(APK Signature Scheme v3): true' in scheme[i]:
                return 'v3'
            else: 
                return 'v2'
    except:
        print("[-] No se pudo obtener el sign scheme uwu")


def generate_keystore():
    if os.path.isfile("custom.keystore"):
        print("[+] custom.keystore file exists")
    else:
        command = ['keytool', '-genkey', '-v', '-keystore', 'custom.keystore', '-alias', 'mykeyaliasname', '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000']
        input_values = '\n'.join(['123123', '123123', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'Unknown', 'yes']).encode('utf-8')
        subprocess.run(command, input=input_values, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def sign_v2(APPDIR, APPOUT):
    try:
        TMP_APPOUT = 'tmp-' + sys.argv[2]
        BASEPATH = os.path.abspath(os.path.dirname(__file__))
        if os.path.isfile(APPOUT):
            os.remove(APPOUT)
        print("[+] Building apk to temp file")
        subprocess.run(["apktool", "build", "--force-all", "--use-aapt",  "-o", TMP_APPOUT, APPDIR], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] Signing temp apk file")
        os.system(f"jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore {BASEPATH}/custom.keystore -storepass 123123 {TMP_APPOUT} mykeyaliasname > /dev/null 2>&1")
        os.system(f"jarsigner -verify -keystore {BASEPATH}/custom.keystore {TMP_APPOUT} > /dev/null 2>&1")
        print("[+] Aligning apk file")
        os.system(f"zipalign -p 4 {TMP_APPOUT} {APPOUT}")
        print("[+] All seems to be right")
        os.remove(TMP_APPOUT)
    except:
        print("[-] Something goes wrong")

def sign_v3(APPDIR, APPOUT):
    try:
        TMP_APPOUT = 'tmp-' + sys.argv[2]
        BASEPATH = os.path.abspath(os.path.dirname(__file__))
        if os.path.isfile(APPOUT):
            os.remove(APPOUT)
        print("[+] Building apk to temp file")
        os.system(f"apktool build --force-all -o {TMP_APPOUT} {APPDIR} > /dev/null 2>&1")
        print("[+] Aligning apk file")
        os.system(f"zipalign -p 4 {TMP_APPOUT} {APPOUT} > /dev/null 2>&1")
        print("[+] Signing apk file")
        os.system(f"apksigner sign --ks {BASEPATH}/custom.keystore --ks-pass pass:123123 --ks-key-alias mykeyaliasname --v2-signing-enabled true {APPOUT} > /dev/null 2>&1")
        os.system(f"apksigner verify {APPOUT} > /dev/null 2>&1")
        os.remove(TMP_APPOUT)
    except:
        print("[-] Something goes wrong")

def main():
    if len(sys.argv) < 3:
        print('Usage {} <decompiled apk folder> <output.apk>'.format(sys.argv[0]))
        exit
    else:
        try:
            APPDIR = sys.argv[1]
            APPOUT = sys.argv[2]
            APK = APPDIR + '.apk'
            check_dependencies()
            sig_scheme = check_signature_scheme(APK)
            print("[*] Signature scheme detected: {}".format(sig_scheme))
            
            if sig_scheme == 'v2':
                generate_keystore()
                sign_v2(APPDIR, APPOUT)
            else:
                sign_v3(APPDIR, APPOUT)
        except KeyboardInterrupt:
            print('\n[</3] uwu')

if __name__ == '__main__':
    main()