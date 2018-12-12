# Copyright (C) 2018 enzok
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.common.constants import CUCKOO_ROOT


# see https://raw.githubusercontent.com/honeynet/cuckooml/master/data/guids.txt

with open(CUCKOO_ROOT+"/data/guid_list.txt", "r") as guidfile:
    GUIDS = {}
    for line in guidfile.read().split("\n"):
        try:
            guid, desc, info = line.split(" ")
            GUIDS[guid] = [desc, info]
        except ValueError:
            pass

class WMIViaCOMApi(Signature):
    name = "WMI_using_COM_API"
    description = "IWbemLocator connection through DCOM to a WMI namespace"
    severity = 2
    confidence = 90
    categories = ["recon"]
    authors = ["enzok"]
    minimum = "1.3"
    evented = True
    match = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CoCreateInstance", "CoGetClassObject", "CoCreateInstanceEx"])

    def on_call(self, call, process):
        if call['api'] == "CoCreateInstance" or call['api'] == "CoCreateInstanceEx":
            clsid = self.get_argument(call, "rclsid")
            if clsid == "4590F811-1D3A-11D0-891F-00AA004B2E24":
                iid = self.get_argument(call, "riid")
                if iid == "DC12A687-737F-11CF-884D-00AA004B2E24":
                    self.data.append({"WMI": "Obtained namespace pointer to WMI interface"})

    def on_complete(self):
        if self.data:
            return True
        else:
            return False

class IEViaCOMApi(Signature):
    name = "IE_using_COM_API"
    description = "Launched IE through DCOM"
    severity = 2
    confidence = 90
    categories = ["stealth"]
    authors = ["enzok"]
    minimum = "1.3"
    evented = True
    match = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CoCreateInstance", "CoGetClassObject", "CoCreateInstanceEx"])

    def on_call(self, call, process):
        if call['api'] == "CoCreateInstance" or call['api'] == "CoCreateInstanceEx":
            clsid = self.get_argument(call, "rclsid")
            if clsid == "0002DF01-0000-0000-C000-000000000046":
                iid = self.get_argument(call, "riid")
                if iid == "EAB22AC1-30C1-11CF-A7EB-0000C05BAE0B":
                    self.data.append({"IWebBrowser Interface": "Internet Explorer started using COM interface"})

    def on_complete(self):
        if self.data:
            return True
        else:
            return False

class COMGUIDs(Signature):
    name = "suspicious_COM_GUIDs"
    description = "Suspicious COM GUIDs"
    severity = 2
    confidence = 90
    categories = ["stealth"]
    authors = ["enzok"]
    minimum = "1.3"
    evented = True
    match = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CoCreateInstance", "CoGetClassObject", "CoCreateInstanceEx"])

    def on_call(self, call, process):
        if call['api'] == "CoCreateInstance" or call['api'] == "CoCreateInstanceEx":
            clsid = self.get_argument(call, "rclsid")
            if clsid and clsid in GUIDS:
                self.data.append({desc: info})

    def on_complete(self):
        if self.data:
            return True
        else:
            return False
