import os
import requests
import pdb
import time
from bs4 import BeautifulSoup
from selenium import webdriver


def exploitdb_query(string):
    # treat str
    list_of_str = string.split(' ')
    new_str = ''
    for word in list_of_str:
        new_str = new_str + word + '+'
    new_str = new_str[:-1]
    # get information
    url = "https://www.exploit-db.com/search?q=" + new_str
    # web browser
    browser = webdriver.Firefox()
    # get data
    browser.get(url)
    time.sleep(5)
    html = browser.page_source
    soup = BeautifulSoup(html)
    table = soup.find('table', {'id': 'exploits-table'})
    browser.quit()
    return table

print(exploitdb_query('Microsoft Windows Server 2008 R2'))
