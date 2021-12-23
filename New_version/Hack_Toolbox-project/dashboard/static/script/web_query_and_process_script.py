import os
import requests
import pdb
import time
from bs4 import BeautifulSoup
from selenium import webdriver


def exploitdb_query(string):
    '''
    @param string: string transmetted by the automate
    @return: html table
    '''
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
    time.sleep(2)
    html = browser.page_source
    soup = BeautifulSoup(html)
    table = soup.find('table', {'id': 'exploits-table'})
    #close browser and quit browser's process
    browser.close()
    browser.quit()
    return table


def retrieve_from_html_exploitdb(data):
    '''

    @param data: data html of the table exploitdb which is the result of the research
    @return: the several row of the research
    '''
    table = data.find('tbody')
    output_rows = []
    if table != None:
        for table_row in table.findAll('tr'):
            columns = table_row.findAll('td')
            output_row = []
            for column in columns:
                output_row.append(column.text)
            while '' in output_row:
                output_row.remove('')
            output_rows.append(output_row)

    return output_rows
