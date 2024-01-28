from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
import boto3
import botocore
import time

# Build the client using the default credential configuration.
client = boto3.client('opensearchserverless')
service = 'aoss'
region = 'us-east-2'
credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key,
                   region, service, session_token=credentials.token)

def createEncryptionPolicy(client):
    try:
        response = client.create_security_policy(
            description='Encryption policy for TV collections',
            name='tv-policy',
            policy="""
                {
                    "Rules": [
                        {
                            "ResourceType": "collection",
                            "Resource": [
                                "collection/tv-*"
                            ]
                        }
                    ],
                    "AWSOwnedKey": true
                }
                """,
            type='encryption'
        )
        print('\nEncryption policy created:')
        print(response)
    except botocore.exceptions.ClientError as error:
        handle_error(error)

def createNetworkPolicy(client):
    try:
        response = client.create_security_policy(
            description='Network policy for TV collections',
            name='tv-policy',
            policy="""
                [{
                    "Description": "Public access for TV collection",
                    "Rules": [
                        {
                            "ResourceType": "dashboard",
                            "Resource": ["collection/tv-*"]
                        },
                        {
                            "ResourceType": "collection",
                            "Resource": ["collection/tv-*"]
                        }
                    ],
                    "AllowFromPublic": true
                }]
                """,
            type='network'
        )
        print('\nNetwork policy created:')
        print(response)
    except botocore.exceptions.ClientError as error:
        handle_error(error)

def createAccessPolicy(client):
    try:
        response = client.create_access_policy(
            description='Data access policy for TV collections',
            name='tv-policy',
            policy="""
                [{
                    "Rules": [
                        {
                            "Resource": [
                                "index/tv-*/*"
                            ],
                            "Permission": [
                                "aoss:CreateIndex",
                                "aoss:DeleteIndex",
                                "aoss:UpdateIndex",
                                "aoss:DescribeIndex",
                                "aoss:ReadDocument",
                                "aoss:WriteDocument"
                            ],
                            "ResourceType": "index"
                        },
                        {
                            "Resource": [
                                "collection/tv-*"
                            ],
                            "Permission": [
                                "aoss:CreateCollectionItems"
                            ],
                            "ResourceType": "collection"
                        }
                    ],
                    "Principal": [
                        "arn:aws:iam::654654164204:user/aoss-author"
                    ]
                }]
                """,
            type='data'
        )
        print('\nAccess policy created:')
        print(response)
    except botocore.exceptions.ClientError as error:
        handle_error(error)

def createCollection(client):
    try:
        response = client.create_collection(
            name='tv-sitcoms',
            type='SEARCH'
        )
        print('\nCollection created:')
        print(response)
    except botocore.exceptions.ClientError as error:
        handle_error(error)

def waitForCollectionCreation(client):
    response = client.batch_get_collection(
        names=['tv-sitcoms'])
    while (response['collectionDetails'][0]['status']) == 'CREATING':
        print('Creating collection...')
        time.sleep(30)
        response = client.batch_get_collection(
            names=['tv-sitcoms'])
    print('\nCollection successfully created:')
    print(response["collectionDetails"])
    host = response['collectionDetails'][0]['collectionEndpoint'].replace("https://", "")
    indexData(host)

def indexData(host):
    client = OpenSearch(
        hosts=[{'host': host, 'port': 443}],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
        timeout=300
    )
    time.sleep(45)
    try:
        response = client.indices.create('sitcoms-eighties')
        print('\nCreating index:')
        print(response)
        response = client.index(
            index='sitcoms-eighties',
            body={
                'title': 'Seinfeld',
                'creator': 'Larry David',
                'year': 1989
            },
            id='1',
        )
        print('\nDocument added:')
        print(response)
    except botocore.exceptions.ClientError as error:
        handle_error(error)

def handle_error(error):
    if error.response['Error']['Code'] == 'ConflictException':
        print('[ConflictException] There is a conflict with an existing resource.')
    else:
        raise error

def main():
    createEncryptionPolicy(client)
    createNetworkPolicy(client)
    createAccessPolicy(client)
    createCollection(client)
    waitForCollectionCreation(client)

if __name__ == "__main__":
    main()
