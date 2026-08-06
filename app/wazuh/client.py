from opensearchpy import OpenSearch
from opensearchpy.exceptions import ConnectionError


def get_client():

    try:

        client = OpenSearch(

            hosts=[
                {
                    "host": "172.16.184.71",
                    "port": 9200
                }
            ],

            http_auth=(
                "admin",
                ""
            ),

            use_ssl=True,

            verify_certs=False,

            ssl_assert_hostname=False,

            ssl_show_warn=False

        )


        # Test connexion
        if client.ping():

            print("Connexion OpenSearch réussie")

        else:

            print(" OpenSearch accessible mais ping échoué")


        return client


    except ConnectionError as e:

        print(
            "Erreur connexion OpenSearch:",
            e
        )

        return None