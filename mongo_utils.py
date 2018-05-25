from pymongo import MongoClient
import json
import os
LOCAL_CONFIG = {
    "_URI": "mongodb://127.0.0.1:27017",
    "_DATABASE": 'androzoo2',
    "_APPLICATION_COLLECTION": 'applications',
    "_ANALYSES_COLLECTION": 'analyses',
    "_ANALYSIS_COLLECTION": 'analysis'
}

REMOTE_CONFIG = {
    "_URI": "mongodb://127.0.0.1:9999",
    "_USERNAME": 'lgitzing',
    "_PASSWORD": 'tout_petit_poney',
    "_ADMIN_DATABASE": 'admin',
    "_DATABASE": 'androzoo2',
    "_APPLICATION_COLLECTION": 'applications',
    "_ANALYSES_COLLECTION": 'analyses',
    "_ANALYSIS_COLLECTION": 'analysis'
}


def connect_to_database(config):
    client = MongoClient(config['_URI'])
    if '_USERNAME' in config and '_PASSWORD' in config and '_ADMIN_DATABASE' in config:
        if client[config['_ADMIN_DATABASE']].authenticate(config['_USERNAME'],
                                                          config['_PASSWORD']):
            print('Connected to database')
            return client
        else:
            print('Can\'t connect to database')
            return None
    print('Connected to database')
    return client

def get_app_data(apk_id):
    client = connect_to_database(LOCAL_CONFIG)
    database = client['androzoo2']
    applications = database['applications']
    analysis = database['analysis']

    app = applications.find_one({'_id':apk_id})
    if app:
        app_analysis = analysis.find_one({'_id':app['last_analysis']})
    if app_analysis and app:
        data = {**app, **app_analysis}
    elif app:
        data = app
    else:
        data = None
    return data

