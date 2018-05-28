"""
A script that collect libc wrappers for syscalls from : https://filippo.io/linux-syscall-table/
"""

import json
import requests
from bs4 import BeautifulSoup

page = requests.get('https://filippo.io/linux-syscall-table/')
soup = BeautifulSoup(page.content, 'lxml')
syscalls = list()
for tr in soup.findAll("tr", {"class", "tbls-entry-collapsed"}):
    tds = tr.findAll("td")
    syscalls.append(tds[1].contents[0])

with open('libc_syscall_wrappers_list.json', 'w') as fp:
    json.dump(syscalls, fp)
