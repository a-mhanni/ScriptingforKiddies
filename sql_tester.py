from traceback import print_tb
from xml.sax.xmlreader import InputSource
from django import forms
import requests
from bs4 import BeautifulSoup as bs 
from urllib.parse import urljoin
from pprint import pprint
import sys


sessh_user = requests.Session()

sessh_user.headers["user agents"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def all_forms_GET(url):
    
    content_of_html = bs(sessh_user.get(url).content,"html.parser")
    
    return content_of_html.find_all("form")

def get_forms_details(form):

    details = {}

    try:
        action = form.attrs.get("action").lower()
    except: 
        action = None
    method = form.attrs.get("method", "get").lower()
    
    element = []

    for  element_method in form.find_all("element"):
        elemnt_type = element_method.attrs.get("type" , "text")
        element_name = element_method.attrs.get("name")
        element_value = element_method.attrs.get("value" , " ")
        element.append({"type": elemnt_type, "name":element_name})
    details["action"] = action
    details["method"] = method 
    details["element"] = element
    return details

def url_vuln_found(response):
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        if error in response.content.decode().lower:
            return True
        return False 

def sql_injection(url):
    for c in "\"'":
        new_url = f"{url}{c}"
        print("Trying SQL injection", new_url)

        res = sessh_user.get(new_url)
        
        if sql_injection(res):

            print("[1] SQL injection is a winner here in this link", new_url)
            return
    formz = all_forms_GET(url)
    print(f"FOund {len(formz)} forms on this {url}.")

    for form_ele in formz:
        form_ele_details = get_forms_details(form_ele)
        for c in "\"'":
            data = {}
            for input_tag in form_ele_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass

                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"

                    url = urljoin(url, form_ele_details["action"])

                elif form_ele_details["method"] == "get":
                    res = sessh_user.get(url, params=data)
            
                if sql_injection(res):
                    print("[+] SQL Injection vulnerability detected, link:", url)
                    print("[+] Form:")
                    pprint(form_ele_details)
                    break
if __name__ == "__main__":
    url = print(input("please provide a url"))
    sql_injection(url)
