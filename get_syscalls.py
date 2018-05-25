import json
import requests
from bs4 import BeautifulSoup




def extract_data_from_html(data):
    tracks_data = list()
    soup = BeautifulSoup(data, 'lxml')
    for div in soup.findAll("div", {"class", "track-item"}):
        test = div.findAll("div", {"class", "infos"})
        truncate = test[0].findAll("div", {"class", "truncate"})
        a = truncate[0].findAll("a")
        if a[0].contents:
            title = a[0].contents[0]
        else:
            title = ""
        if truncate[1].contents:
            artist = truncate[1].contents[0]
        else:
            artist = ""
        for child_div in div.findAll("div"):
            if child_div.has_attr("data-soundcloud"):
                soundcloud_id = child_div['data-soundcloud']
        track_category_node = div.findAll("div", {"class", "track-category"})
        track_category = track_category_node[0].contents[0].replace("\xa0", "")
        track_data = {
            'soundcloud_id': soundcloud_id,
            'genre': track_category,
            'title': title,
            'artist': artist
        }
        tracks_data.append(track_data)
    return tracks_data


def does_page_exists(data):
    soup = BeautifulSoup(data, 'lxml')
    h2 = soup.findAll("h2", text='Not Found')
    return len(h2) == 0


all_tracks = list()

counter = 0
page_exists = True

page = requests.get('https://filippo.io/linux-syscall-table/')
soup = BeautifulSoup(page.content, 'lxml')
syscalls = list()
for tr in soup.findAll("tr", {"class", "tbls-entry-collapsed"}):
    tds = tr.findAll("td")
    syscalls.append(tds[1].contents[0])

all_tracks = {}
with open('result.json', 'w') as fp:
    json.dump(syscalls, fp)
