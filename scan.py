import requests
import sys
from bs4 import BeautifulSoup
import urljoin

## session of http
s = requests.session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0"


def get_forms(url):
    # extract html web forms
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")


def form_details(form):
    # create function that returns form details
    detailsOfForms = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value
        })

    detailsOfForms['action'] = action
    detailsOfForms['method'] = method
    detailsOfForms['inputs'] = inputs

    return detailsOfForms


def vulnerable(response):
    # this function will look for vulnerabilities
    errors = {
        "quoted strings not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your SQL syntax"
    }

    for error in errors:
        if error in response:
            return True
        return False


def sql_injection_scan(url):
    # this function will do the actual scan

    forms = get_forms(url)
    print(f'[+] Detected {len(forms)} forms on {url}.')

    for form in forms:
        details = form_details(form)
        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + i
                elif input_tag["type"] != 'submit':
                    data[input_tag['name']] = f'test{i}'
            res = ""
            if details["method"] == "post":
                res = s.post(url, data = data)
            elif details["method"] == "get":
                res = s.get(url, params = data)

            if vulnerable(res):
                print("SQL Injection Attack vulnerability in link: ", url)
                return

    print("No vulnerabilities")


url = "https://github.com"
sql_injection_scan(url)


