#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of Androwarn.
#
# Copyright (C) 2012, 2019 Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# Androwarn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androwarn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androwarn.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

# Global imports
import sys
import os
import re
import logging
import argparse
import json
import ast
import pickle

# Androwarn modules import
from warn.search.search import grab_application_package_name, grab_application_detail
from warn.analysis.analysis import perform_analysis
from warn.report.report import dump_analysis_results
from warn.report.report import generate_report

# Androguard import
try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    sys.exit("[!] The androguard module is not installed, please install it and try again")

CONFIG_DIR = './config/'

# Logger definition
log = logging.getLogger('log')
log.setLevel(logging.ERROR)
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
log.addHandler(handler)

# Script version
VERSION = '1.6'
print('[+] Androwarn version %s\n' % VERSION)

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)

# Options definition
parser.add_argument('-i', '--input', help='APK file to analyze', required=True, type=str)
parser.add_argument('-o', '--output',
                    help='Output report file (default "./<apk_package_name>_<timestamp>.<report_type>")', type=str)
parser.add_argument('-v', '--verbose', help='Verbosity level (ESSENTIAL 1, ADVANCED 2, EXPERT 3) (default 1)', type=int,
                    choices=[1, 2, 3], default=1)
parser.add_argument('-r', '--report', help='Report type (default "html")', choices=['txt', 'html', 'json'], type=str,
                    default='html')
parser.add_argument('-d', '--display-report', help='Display analysis results to stdout', action='store_true',
                    default=False)
parser.add_argument('-L', '--log-level', help='Log level (default "ERROR")', type=str,
                    choices=['debug', 'info', 'warn', 'error', 'critical', 'DEBUG', 'INFO', 'WARN', 'ERROR',
                             'CRITICAL'], default="ERROR")
parser.add_argument('-w', '--with-playstore-lookup', help='Enable online lookups on Google Play', action='store_true',
                    default=False)


def main():
    global parser
    options = parser.parse_args()
    log.debug("[+] options: %s'" % options)

    # Log_Level
    try:
        log.setLevel(options.log_level.upper())
    except:
        parser.error("Please specify a valid log level")

    # Input
    print("[+] Loading the APK file...")
    a, d, x = AnalyzeAPK(options.input)
    package_name = grab_application_package_name(a)

    # Get Application Detail
    app_detail = grab_application_detail(package_name)

    # Analysis
    data = perform_analysis(options.input, a, d, x, options.with_playstore_lookup)

    # Synthesis
    # if options.display_report:
    #     Brace yourself, a massive dump is coming
    #     dump_analysis_results(data,sys.stdout)
    #
    remain_permission = check_permissions(app_detail, data)

    data[3]['androidmanifest.xml'][2]=('permissions',remain_permission)

    log.error(data[3])

    # generate_report(package_name, data, options.verbose, options.report, options.output)


def check_permissions(app_detail, data):
    if app_detail:
        log.error("co")
        remain_permission = check_permissions_helper(app_detail, data)
    else:
        log.error("khong")
        remain_permission = getAppPermissions(data)
    return_permissions = []
    if len(remain_permission) != 0:
        danger_permission = getDangerrousPermissions()
        critical_per = danger_permission['critical']
        warning_per = danger_permission['warning']
        for critical in critical_per:
            if critical in remain_permission:
                remain_permission[critical] = 2
        for warning in warning_per:
            if warning in remain_permission:
                remain_permission[warning] = 1
        for key, value in remain_permission.items():
            new_value = str(key)
            if value != 0:
                new_value = str(key) + "__-__" + str(value)
            return_permissions.append(new_value)
    return return_permissions


def check_permissions_helper(app_detail, data):
    permission_data = getAppPermissions(data)
    config_permissions = getConfigPermissions(app_detail)
    for permission in config_permissions:
        permission_data.pop(permission, "None")
    return permission_data


def getAppPermissions(data):
    raw_data = data[3]['androidmanifest.xml'][2][1]
    permission_data = []
    for raw in raw_data:
        index = raw.find(':')
        index = index + 1
        permission_data = permission_data + ast.literal_eval(raw[index:].strip())

    category_permissions = dict(zip(permission_data, [0] * len(permission_data)))
    return category_permissions


def getConfigPermissions(app_detail):
    with open(getConfigPath(app_detail), 'r') as file:
        config_data = json.load(file)
    return config_data['permissions']


def getDangerrousPermissions():
    with open(CONFIG_DIR + 'permissions.json', 'r') as file:
        config_data = json.load(file)
    return config_data


def getConfigPath(app_detail):
    global CONFIG_DIR
    return CONFIG_DIR + 'permissions/' + str(app_detail['category'][0]).lower() + ".json"


if __name__ == "__main__":
    main()