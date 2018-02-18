from appJar import *
from collections import Counter
from collections import OrderedDict
import requests
from AccessLog import toJson
import hashlib
import time
import json
from datetime import datetime
import os

class LogParse:
    def __init__(self):
        self.file = ''
        self.iplist = []
        self.l = []
        self.country = []

        # App config
        self.app = gui("Log Analyzer", "500x800")
        fileMenus = ["Save Figure..."]
        self.app.addMenuList("File", fileMenus, self.save)
        self.app.addStatusbar(fields=2)
        self.app.setStatusbarWidth(1, 1)
        self.app.setStatusbar("Dev: Thanawat, Dechdumrong", 0)
        self.app.setStatusbar("Version 1.0", 1)
        self.app.addButtons(["Select File", "Help"], [self.select, self.help], row=0, column=0)
        self.app.addLabelEntry("IP", row=1)
        self.app.addButtons(["Go", "Set"], [self.go, self.set], row=2)
        self.app.startPanedFrame("p1")
        self.app.datePicker("dp")
        self.app.setDatePicker("dp")
        self.app.addLabel("t", "Start")
        self.app.startPanedFrame("p2")
        self.app.datePicker("dp2")
        self.app.setDatePicker("dp2")
        self.app.addLabel("t2", 'Stop')
        self.app.stopPanedFrame()
        self.app.stopPanedFrame()

        # Basemap
        self.basemaptitle = "Embedded Basemap"
        self.app.addBasePlot(self.basemaptitle)

        self.lonlat = 40.730610
        self.lonlon = -73.935242

    def save(self, btn=None):
        self.savedir = self.app.saveBox("Save figure", fileTypes=[('images', '*.png')])
        self.app.saveFig(self.savedir)
        print("Save!")

    def __toJson(self):
        self.convert = toJson(self.file)
        self.jsonfile = "{}_Json.json".format(self.file)
        self.convert_logs = open(self.jsonfile, 'w')
        self.convert_logs.write(self.convert)
        self.dictcon = json.loads(self.convert)
        return self.dictcon

    def hostlist(self):
        self.hntlist = list(self.dictcon.values())
        self.ipfile = "{}_IP.txt".format(self.file)
        self.write_ip = open(self.ipfile, "w")
        self.hnt = {'ip' : [], 'timestamp' : []}
        dp = self.app.getDatePicker("dp")
        dp2 = self.app.getDatePicker("dp2")
        if dp == datetime.today().date() and dp2 == datetime.today().date():
            for eachline in self.hntlist:
                (self.hnt['ip'].append(eachline.get('HOST')))
                (self.hnt['timestamp'].append(str(eachline.get('TIME')).split(':')[0]))
        else:
            for eachline in self.hntlist:
                tstamp = str(eachline.get('TIME')).split(':')[0]
                tstamps = time.mktime(datetime.strptime(tstamp, "%d/%b/%Y").timetuple())
                tstamp2 = datetime.strptime(tstamp, "%d/%b/%Y")
                dts = datetime.date(tstamp2)
                # print(type(tstamps), type(tstamp2), tstamp2)
                if dts <= dp2 and dts >= dp:
                    self.hnt['ip'].append(eachline.get('HOST'))
                    self.hnt['timestamp'].append(str(eachline.get('TIME')).split(':')[0])

        for lines in self.hnt['ip']:
            self.write_ip.write(lines + "\n")

        print(self.hnt['ip'])
        print(self.hnt['timestamp'])

    def md5(self):
        # Write new md5
        print("Yes md5")
        self.file_database = "plogs.txt"
        self.database = open(self.file_database, 'a')
        self.hashmd5 = hashlib.md5(open(self.file,'rb').read()).hexdigest()
        self.database.write(self.hashmd5 + " " + time.strftime("%H:%M:%S") + " " + time.strftime("%d/$m/%Y") + "\n")

    def check_md5(self):
        # To check md5
        try:
            self.rdb = open(self.file_database, 'r')
            found = False
            for line in self.rdb:
                if self.hashmd5 in line and os.path.isfile("{}_coor.txt".format(self.file)) :
                    return True
            return False
        except AttributeError:
            self.app.warningBox("WARNING", "Please select file!")

    def check_cal(self):
        # New Calculation
        if not self.check_md5():
            print("Yes1")
            self.__toJson()
            self.hostlist()
        else:
            pass

    def ip_json(self):
        # String filter
        self.lines = self.convert.split(',')

        self.host = [item for item in self.lines if "HOST" in item]
        self.times = [item for item in self.lines if "TIME" in item]

        self.str_host = str(self.host)
        self.str_times = str(self.times)

        self.list_str_times = list(self.str_times)

        self.timetrans = str.maketrans('', '', 'TIME{}[]')
        self.trans = str.maketrans('', '', 'HOST{}:[]')

        self.line = self.str_host.translate(self.trans)
        self.times_line = self.str_times.translate(self.timetrans)

        self.times_trans = self.times_line.split(",")
        self.host_trans = self.line.split(",")

        self.deleted = []
        self.iplist = []
        self.timess = []
        print(self.iplist)

        for i in self.times_trans:
            freplace = i[1:].replace('"', '')
            treplace = freplace.replace("'", '')
            threplace = treplace.replace(' ', '')
            forreplace = " -".join(threplace.split("-"))
            timestamps = datetime.strptime((forreplace[1:]), "%d/%b/%Y:%H:%M:%S %z")
            self.timess.append(timestamps.timestamp())

        for word in self.host_trans:
            replaced = word.replace(word[0:7], '').strip("\'")
            self.deleted.append(replaced)
        for i, words in enumerate(self.deleted):
            replaced2 = words.replace('""', "").strip(" ' ")
            replaced3 = replaced2.replace('"', "")
            if self.timess[i] > self.ts and self.timess[i] < self.ts2:
                self.iplist.append(replaced3)

        print(self.iplist)

    def select(self, btn=None):
        # Select file
        self.file = self.app.openBox("Select")
        self.md5()

    def help(self, btn=None):
        self.app.infoBox("Help", "Select IPs file and click Set or Show if it's currently SET\n"
                                 "OR Write single Ip, multi-Ip in the entry and do the same")

    def show(self, btn=None):
        # Update plot
        self.coor = "{}_coor.txt".format(self.file)
        self.ll = []
        f = open(self.coor, 'r')
        for line in f:
            a = line.split()
            print(a)
            self.ll.append([a[1], a[2]])
        f.close()
        self.app.setBasemap(self.basemaptitle, self.ll)

        if self.check_md5():
            ll = []
            print("No! from show")
            citynum = "{}_outp.txt".format(self.file)
            citynum_file = open(citynum, 'r')
            for line in citynum_file:
                ll.append(line[:-1])
            # print(cn, "cn")
            citynum_file.close()

            dc = dict(Counter(ll))
            self.app.addPieChart("p1", dc)


    def set(self, btn=None):
        # Set plot to Basemap
        if self.file == '':
            self.app.warningBox("WARNING", "Please select file!")
        else:
            self.check_cal()
            if not self.check_md5():
                self.p = open('{}_coor.txt'.format(self.file), 'w+')
                test = open('{}_outp.txt'.format(self.file), 'w+')
                dp = self.app.getDatePicker("dp")
                dp2 = self.app.getDatePicker("dp2")
                print("ssss", list(OrderedDict.fromkeys(self.hnt['ip'])))
                for ip in list(OrderedDict.fromkeys(self.hnt['ip'])):
                    request = requests.get('http://ip-api.com/json/'+ip)
                    request_json = request.json()

                    try:
                        if request_json['status'] == 'fail':
                            pass
                        else:
                            print("{}, {}, {}".format(ip, request_json['lat'],  request_json['lon']))
                            self.country.append(request_json['country'])
                            self.p.write("{} {} {}\n".format(ip, request_json['lon'], request_json['lat']))
                            test.write("{}\n".format(request_json['country']))
                            self.app.setBasemap(self.basemaptitle, [[request_json['lon'], request_json['lat']]])
                    except KeyError:
                        pass
                self.p.close()
                test.close()
                print("Country", dict(Counter(self.country)))

            else:
                print("No! from set")
                self.coor = "{}_coor.txt".format(self.file)
                citynum = "{}_citnum.txt".format(self.file)
                dc = dict(Counter(self.country))
                print(dict(Counter(self.country)))
                # self.app.addPieChart("p1", dc)
                dc_str = str(dc)
                citynum_file = open(citynum, 'w')
                citynum_file.write(dc_str)
                citynum_file.close()
                self.show()
            self.coor = "{}_coor.txt".format(self.file)
            citynum = "{}_citnum.txt".format(self.file)
            dc = dict(Counter(self.country))
            # print(dict(Counter(self.country)))
            try:
                self.app.addPieChart("p1", dc)
            except:
                self.app.removePieChart("p1")
                self.app.addPieChart("p1", dc)
            dc_str = str(dc)
            citynum_file = open(citynum, 'w')
            citynum_file.write(dc_str)
            citynum_file.close()

    def go(self, btn=None):
        # For single IP or Multi Ip input
        ip = self.app.getEntry("IP")
        if ip == '':
            self.app.warningBox("WARNING", "Please input an IP!")
        else:
            ips = ip.split("\n")
            if len(ips) == 1:

                request = requests.get('http://ip-api.com/json/'+ips[0])
                request_json = request.json()
                self.app.setLabel("is", "Lat: {} Long: {} Country: {}, City: {}".format(request_json['lat'],
                                                                                        request_json['lon'], request_json['country'], request_json['city']))
                self.app.setBasemap(self.basemaptitle, [[request_json['lon'], request_json['lat']]])
            else:
                for ip in ips:
                    try:
                        request = requests.get('http://ip-api.com/json/'+ip)
                        request_json = request.json()
                        self.country.append(request_json['country'])
                        self.app.setBasemap(self.basemaptitle, [[request_json['lon'], request_json['lat']]])
                    except KeyError:
                        pass

    def run(self):
        self.app.go()


if __name__ == '__main__':
    lp = LogParse()
    lp.run()
