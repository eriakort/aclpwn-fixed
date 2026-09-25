# Fixed: 'from neo4j.v1 import GraphDatabase' removed in neo4j driver 2.0+
# Use top-level import instead.
from neo4j import GraphDatabase
import requests

driver = None
restapi = None

def init(host, user, password):
    global driver, restapi
    driver = GraphDatabase.driver("bolt://%s:7687" % host, auth=(user, password))
    restapi = requests.Session()
    restapi.auth = (user, password)
