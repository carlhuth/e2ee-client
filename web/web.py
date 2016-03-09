import bottle
from bottle import route, run, template, static_file
import json
import sys
import os

project_dir = '/home/miha/projects/e2ee-client'
web_static = os.path.join(project_dir, "web/static/")
web_template = os.path.join(project_dir, "web/views/htemplate")
#web_template = os.path.join(project_dir, "web/views/test")
web_domain="localhost" # no slashes
web_port=8000

@route('/static/:filename#.*#')
def send_static(filename):
    return static_file(filename, root='./static/')

@route('/')
def hello():
    return template(web_template)
   
bottle.debug(True) 
run(host=web_domain, port=web_port)




