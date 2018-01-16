# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import tempfile
from json import loads

from lib.common.abstracts import Package

class Applet(Package):
    """Java Applet analysis package."""
    PATHS = [
        ("ProgramFiles", "Mozilla Firefox", "firefox.exe"),
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    def make_html(self, path, class_name, param_list):
        params = ""

        if param_list:
            params = loads(param_list)
            for name in params:
                params += """
                <param name="%s" value="%s" />
                """ % (name, param_list[name])
        html_start = """
        <html>
            <body>
                <applet archive="%s" code="%s" width="1" height="1">
        """ % (path, class_name)
        html_end = """
                </applet>
            </body>
        </html>
        """

        html = html_start + params + html_end

        _, file_path = tempfile.mkstemp(suffix=".html")
        with open(file_path, "w") as file_handle:
            file_handle.write(html)

        return file_path

    def start(self, path):
        browser = self.get_path("browser")
        class_name = self.options.get("class")
        param_list = self.options.get("applet_params")
        html_path = self.make_html(path, class_name, param_list)
        return self.execute(browser, "\"%s\"" % html_path, html_path)
