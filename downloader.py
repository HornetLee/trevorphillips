import base64
import getpass
import os
import shutil
import sys
import tempfile
import re

import configparser as ConfigParser
from urllib.request import urlopen
from urllib.request import Request
from urllib.request import build_opener
from urllib.request import install_opener
from urllib.request import HTTPCookieProcessor
from http.cookiejar import CookieJar
from urllib.parse import urlencode
from urllib.error import HTTPError

try:
    from bs4 import BeautifulSoup
except:
    print("#{0:<80}#".format(" Please install BeautifulSoup python module."))
    if sys.version_info >= (3, 0):
        print("#{0:<80}#".format("  > sudo apt-get install python3-bs4"))
    else:
        print("#{0:<80}#".format("  > sudo apt-get install python-bs4"))
    sys.exit(-1)

class QuickBuild():
    url_base = 'https://android.qb.sec.samsung.net'
    url_login = url_base + '/signin'
    url_main = url_base + '/dashboard'
    url_build = url_base + '/build/'
    LOGIN_INFO = 'LoginInfo'

    login_status = False
    valid_url = None
    config_filename = '.login.cfg'
    approot = os.path.dirname(os.path.abspath(sys.argv[0]))
    config_path = os.path.join(approot, config_filename)
    tempdir = os.path.join(tempfile.gettempdir(), 'get_ramdisk')
    #targetdir = os.path.join(approot, 'debug_ramdisk')
    html = None

    def __init__(self, build_id):
        if not build_id.isdigit():
            tmp = re.match('.*/([0-9]+)$',build_id)
            if tmp is not None:
                build_id = tmp.group(1)
            if not build_id.isdigit():
                print("Your link is %s" % build_id)
                print("Should be PBS ID as number or full link")
                sys.exit(-1)
        self.build_id = build_id
        self.ramdisk_path = None
        self.targetdir = os.path.join(self.approot,'qb_bin',build_id)
    def GetLoginInfo(self):
        config = ConfigParser.RawConfigParser()

        if os.path.isfile(self.config_path) is False:
            return None, None

        config.read(self.config_path)

        if config.has_section(self.LOGIN_INFO) is False:
            return None, None

        userid = config.get(self.LOGIN_INFO, 'userid')
        passwd = base64.b64decode(str.encode(config.get(self.LOGIN_INFO, 'passwd')))
        return userid, passwd

    def SetLoginInfo(self, userid, passwd):
        config = ConfigParser.RawConfigParser()

        config.add_section(self.LOGIN_INFO)
        config.set(self.LOGIN_INFO, 'userid', userid)
        config.set(self.LOGIN_INFO, 'passwd', base64.b64encode(passwd.encode("ascii")).decode("ascii"))

        with open(self.config_path, 'w') as configfile:
            config.write(configfile)

        return

    def Login(self):
        print("#{0:-<80}#".format(""))
        print("#{0:<80}#".format(" Login..."))

        if self.login_status is True:
            return False

        userid, passwd = self.GetLoginInfo()

        if userid is None or passwd is None:
            print("#{0:<80}#".format(" Please enter the new LoginInfo"))
            if sys.version_info > (3, 0):
                userid = input("userid : ")
            else:
                userid = raw_input("userid : ")
            passwd = getpass.getpass()
            self.SetLoginInfo(userid, passwd)

        logininfo = {
            'userName': userid,
            'password': passwd,
            'remember': True
        }

        cj = CookieJar()
        opener = build_opener(HTTPCookieProcessor(cj))
        install_opener(opener)

        data = urlencode(logininfo)
        if sys.version_info >= (3, 0):
            data = data.encode("utf-8")

        soup = BeautifulSoup(urlopen(self.url_login).read(), "html.parser")
        # soup = BeautifulSoup(urlopen(self.url_login).read())
        action = soup.form['action']
        login_url = self.url_base + '/' + action

        req = Request(login_url, data)
        self.openurl = urlopen(req)

        if self.openurl.geturl() == self.url_main:
            self.login_status = True
            print("#{0:<80}#".format(" Login Success!!"))
            return True
        else:
            print("#{0:<80}#".format(" Login Failed!! Please check the login info!!"))
            os.remove(self.config_path)
            return False

    def DownloadFileFromUrl(self, url, targetdir):
        if url is None:
            print("#{0:<80}#".format(" url doesn't exist or maybe removed!"))
            return None

        rexp = re.search('filename=(.+.(md5|tar))', url)
        if rexp is None:
            print("#{0:<80}#".format(" Can't download file!!"))
            return None
        filepath = os.path.join(targetdir, rexp.group(1))
        try:
            resp = urlopen(url)
        except HTTPError as e:
            if e.getcode() == 500:
                content = e.read()
            else:
                raise

        with open(filepath, 'wb') as out_file:
            shutil.copyfileobj(resp, out_file)

        self.ramdiskfile = rexp.group(1)
        self.ramdisk_path = filepath
        return filepath

    def Download(self, targetdir):
        print("#{0:-<80}#".format(""))
        print("#{0:<80}#".format(" Download AP / OMC bin..."))

        if self.login_status is False and self.Login() is False:
            return False

        self.openurl = urlopen(self.url_build + self.build_id)
        if self.openurl is None:
            return False
        self.html = self.openurl.read()
        if self.html is None:
            return False

        soup = BeautifulSoup(self.html, "html.parser")
        # soup = BeautifulSoup(self.html)

        resp = soup.find('a', {'href': re.compile('AP_.+md5')})
        if resp is None:
            print("#{0:<80}#".format(" Can't find the output files!!"))
            return False
        else:
            url = self.url_base + resp['href']

        print("#{0:<80}#".format("    %s" % url.split('=')[-1]))
        self.DownloadFileFromUrl(url, targetdir)

        print("#{0:-<80}#".format(""))
        print("#{0:<80}#".format(" Downloaded AP BIN successfully!!"))

        resp = soup.find('a', {'href': re.compile('CSC_OMC_.+md5')})
        if resp is None:
            print("#{0:<80}#".format(" Can't find the output files for CSC_OMC"))
            return True
        else:
            url = self.url_base + resp['href']

        print("#{0:<80}#".format("    %s" % url.split('=')[-1]))
        self.DownloadFileFromUrl(url, targetdir)

        print("#{0:-<80}#".format(""))
        print("#{0:<80}#".format(" Downloaded CSC_OMC BIN successfully!!"))
        return True
       

    def run(self):
        return self.Download(self.targetdir)


if __name__ == '__main__':
    q = QuickBuild(sys.argv[1])
    if q.run():
        with open(".tmp_debug_ramdisk_file_name", 'w') as output:
            output.write(str(q.ramdiskfile))
        sys.exit(0)
    else:
        sys.exit(-1)
