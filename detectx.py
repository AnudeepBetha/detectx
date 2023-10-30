#!/usr/bin/env python3

import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import requests
import typer
import shutil
import validators
from payloads import sqli_payloads_array, xss_payloads_array
from Regex import regex_patterns
import inquirer
import click
from halo import Halo

detectx_app = typer.Typer()
spinner = Halo (text = 'Processing!!', spinner = 'star')


MODE_CHOICES = ["SQLi", "XSS"]
DB_CHOICES = ["MySQL", "Oracle", "PostgreSQL", "Microsoft SQL Server", "Microsoft Access"]



def banner():
    """Dynamic banner based on the size of the terminal"""
    columns, _ = shutil.get_terminal_size()

    banner = [
                "                                                           ",
                "██████╗ ███████╗████████╗███████╗ ██████╗████████╗██╗  ██╗ ",
                "██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝╚██╗██╔╝ ",
                "██║  ██║█████╗     ██║   █████╗  ██║        ██║    ╚███╔╝  ",
                "██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║    ██╔██╗  ",
                "██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ██╔╝ ██╗ ",
                "╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ",
                "                                                           ",
    ]

    for line in banner:
        typer.echo(line.center(columns))

# Method to find if the given website contains any forms 
# Using Beautiful Soap Library to extract Forms and their data
def get_all_forms(url):
    
    # Making a GET Request on the given URL to find the form data
    response = requests.get(url)

    # Using Beautiful Soap Package to extract forms in the website
    
    parsed_html_form_data = BeautifulSoup(response.content, "html.parser").find_all("form")
    
    return parsed_html_form_data

def individual_form_detials(form):
    
    # Initializing Form Details Dictionary
    form_details = {}
    
    # First finding the action and Methods of the form, to submit the form to that URL.
    
    form_action = form.get("action",None)
    if form_action: 
        form_action = form_action.lower()
    
    form_method = form.get("method","get").lower()
    
    # Extract only the Inputs of the form to submit the payloads
    
    input_tags = form.find_all("input")
    input_details = []
    
    for input_tag in input_tags:
        
        input_type = input_tag.get("type","text")
        input_name = input_tag.get("name")
        input_value = input_tag.get("value","")
        input_details.append({"type": input_type, "name": input_name, "value": input_value})
    form_details.update({"action":form_action, "method": form_method, "inputs":input_details})        
    
    return form_details

def submit_form(mode, url, database):
    

    
    spinner.start()
    all_forms = get_all_forms(url)
    sqli_payloads =["", "\'", "\""]
    if mode == 'SQLi':
        
        if all_forms:
            typer.echo(f"\n Found the following {len(all_forms)} forms on the website ")
            # Now getting html tag details and their values in each form.
            for form in all_forms:
                form_details = individual_form_detials(form)
                for payload in sqli_payloads:
                    payload_data = {}
                    for input_tag in form_details["inputs"]:
                        if input_tag["type"] == "hidden" or input_tag["value"]:
                            try:
                                payload_data[input_tag["name"]] = input_tag["value"] + payload
                            except:
                                pass
                        elif input_tag["type"] != "submit":
                            payload_data[input_tag["name"]]= "injection_detection" + payload
        
    elif mode == 'XSS':
        if all_forms:
            for form in all_forms:
                    form_details = individual_form_detials(form)
                    for payload in xss_payloads_array:
                        payload_data={}
                        for input_tag in form_details["inputs"]:
                            if input_tag["type"] == "text" or input_tag["type"] == "search":
                                input_tag["value"] = payload
                            if input_tag.get("name") and input_tag.get("value"):
                                payload_data[input_tag.get("name")] = input_tag.get("value")
        else: 
            spinner.succeed(" Scan Completed!")
            click.echo("\n")
            click.echo(click.style("\n No Forms found on the Website!\n",fg="Green", bold= True))
            click.echo(click.style(f"\n No {mode} Vulnerability found on {url} \n",fg="Green", bold= True))
            return
                
    
    new_url = urljoin(url, form_details["action"])
    if form_details["method"] == "post":
        response = requests.post(new_url, data=payload_data)
    else:
        response = requests.get(new_url,params=payload_data)
    
    if is_response_vulnerable(mode, response, database):
            spinner.succeed("Scan Completed!")
            click.echo("\n")
            click.echo(click.style(f"\n Detected  {mode} Vulnerability",fg="red", bold=True))
            click.echo(click.style(f"\n URL: {new_url} \n",fg="red"))
    else:
            spinner.succeed("Scan Completed!")
            click.echo("\n")
            click.echo(click.style(f"\n Detected  {mode} Vulnerability",fg="red", bold=True))
            click.echo(click.style(f"\n URL: {new_url} \n",fg="red"))
        

# Method to check whether a response is vulnerable depending on the mode and database(in case of sqli mode)
def is_response_vulnerable(mode, response, database):
    
    response = response.content.decode().lower()
    if mode == 'SQLi':
        regex_patterns_for_db = []
        # Populating the regex_patterns_for_db Array if any database is mentioned, 
        # Else going to populate it with all regex patterns irrespective of database
        # By Default, without the Database supplied, the DetectX checks the response against all available Databases. 
        if database in DB_CHOICES:
            for key, value in regex_patterns.items():
                if key.lower() == database.lower():
                    regex_patterns_for_db.extend(value)
        else :
            for value in regex_patterns.values():
                regex_patterns_for_db.extend(value)
                
        # Now checking the content of reponse has any sql errors using Regular Expression Search Mode
        for regex_pattern in regex_patterns_for_db:
            if re.search(regex_pattern, response, re.IGNORECASE):
                return True
    
    elif mode == 'XSS':
        for payload in xss_payloads_array:

            if payload.lower() in response.lower():
                return True
     
            
    return False
    

def sqli_detect(mode, url, database):
    
    # iterate through payloads for SQL Injection, referred Payload Box to construct the Payloads Array
    # Sending Payloads by appending them with URL
    click.echo(click.style("Starting URL Reponse Analysis Stage", fg="blue", bold=True))
    spinner.start()
    for payload in sqli_payloads_array:
        
        new_url = url + payload
        #
        try:
            response = requests.get(new_url)
        except requests.HTTPError as httperr:
            spinner.succeed("Scan Completed!!")
            click.echo("\n")
            click.echo(click.style(f"{httperr}", fg= "red"))
            
            
        # Checking if the Response Received contains SQL Errors according to Database if the database is supplied.
        
        if is_response_vulnerable(mode, response, database):
            spinner.succeed("Scan Completed!!")
            click.echo("\n")
            click.echo(click.style(f"\n Detected  {mode} Vulnerability",fg="red"))
            click.echo(click.style(f"\n URL: {new_url}",fg="red"))
            return True
    
    spinner.succeed(" No SQL Injection Vulnerability Found using URL on the website. ")
        
    click.echo("\n")    
    click.echo(click.style("Starting HTML Reponse Analysis Stage", fg="blue", bold=True ))
    # Sending Payloads in the forms (if present) on the Target Website  
    # Finding if any forms are present on the Target Website
    
    submit_form(mode, url, database)

def xss_detect(mode, url, database):

    
    submit_form(mode, url, database)

    

@detectx_app.command()
def detectx(
                mode: str = typer.Option(None, "--mode", "-m"),
                url: str = typer.Option("", "--url", "-u"),
                database:str =  typer.Option("None", "--db", "-d")):

    if mode == None:
        mode = inquirer.list_input("Detect SQL Injection or Cross Site Scripting", choices = MODE_CHOICES )
    
    if url == "":
        url = inquirer.text("Enter the URL of the Website intended to be tested")   
    
    if not validators.url(url):
        typer.echo(f" Invalid URL: {url}")
        raise typer.Exit()
    
    if database == "None" and mode == 'SQLi':
         database = inquirer.text(f"""Enter the website’s database if known. Else, leave blank to check - {DB_CHOICES}""")

    
    if mode == 'SQLi':
        sqli_detect(mode, url, database)
    if mode == 'XSS':
        spinner.start()
        xss_detect(mode, url, database)
        
    
    
    return

if __name__ == "__main__" :
    banner()
    detectx_app()

    # sqli_detect("sqli","http://testphp.vulnweb.com/artists.php?artist=1", "Any")
    # xss_detect("xss", "https://xss-game.appspot.com/level1/frame", "")
    # xss_detect("xss", "http://testfire.net/", "")

    
